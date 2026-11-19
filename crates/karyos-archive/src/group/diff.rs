// SPDX-License-Identifier: Apache-2.0

//! The first difference between two recording group journals
//! (`quantstratum-docs: karyos/design/recording-group-replay.md` section
//! 10; R-CORE-49): the public, typed comparison that `karyos-replay diff`
//! prints.
//!
//! [`diff`] recovers both journals, compares their headers, then their
//! events in order over the range, record by record: the input event,
//! each observation, and the event's end. It reads only. Both journals are
//! recovered through [`ReadOnly`], so one that recovery would repair (a
//! torn tail) is an error, never repaired; it opens no driver.
//!
//! **The comparison basis.** Every recorded field of the events is
//! compared, nothing is excluded (karyos#780); recorded checkpoints are the
//! stated exception below. It compares records, never payload bytes: a
//! payload by reference is compared as its reference, and a captured
//! output by its length and CRC-32C under record version 1 (karyos#675).
//! The complete prefix is bounded only by incomplete events and gap
//! markers; a payload not captured, or a reference unavailable, in the
//! range is not comparable. The first difference is the one at the lowest
//! `group_seq`, then the lowest observation index.
//!
//! Recorded checkpoints (template 30, A8-2) are compared as records,
//! matched by `group_seq`: their length, crc32c and format take part in
//! equality; their `checkpoint_id` and `position` do not (each journal
//! numbers and places its own checkpoints), so `Identical` certifies the
//! same state at the same events, not the same ids. A difference in a
//! compared field, or a checkpoint on one side only, is
//! [`Kind::StateCheckpoint`].
//! [`DiffRequest::from_checkpoint`] opens the left journal at its
//! checkpoint and the right one at its checkpoint with the same
//! `group_seq`, each through its store opened read only: what the store's
//! recovery would cut or mark lost reads as lost, so a damaged checkpoint
//! is not comparable.
//!
//! **The outcome.** [`Report::Identical`] only over the same declared,
//! complete, comparable range of both journals under that basis. An input
//! shorter than the range, a gapped, corrupt or unsupported-version
//! record, a manifest difference not accepted, or a missing checkpoint is
//! [`Report::NotComparable`] or [`Report::Error`], with the reason; never
//! `Identical`.

use crate::disk::{Disk, ReadOnly};
use crate::group::checkpoint::{CheckpointStore, recorded_end};
use crate::group::journal::{GroupJournal, JournalConfig, JournalError};
use crate::group::prefix::{CheckpointHeld, Coverage, recover, recover_ranges};
use crate::group::record::{
    CONTRACT_VERSION, CheckpointRecord, GroupRecord, Operation, Payload, Role, UnsupportedHeader,
};
use crate::group::replay::{
    CursorConfig, ReplayConfig, ReplayCursor, ReplayError, ReplayEvent, Step, Stop,
};
use crate::segment::{SegmentError, SyncPolicy, recorded_geometry};
use std::path::PathBuf;

/// The records one event may hold, its first, its observations and its
/// end: an event past it is [`Report::Error`].
const MAX_RECORDS: usize = 16_384;
/// The events the prefix recovery holds waiting at once.
const RECOVERY_CAPACITY: usize = 64;

/// One journal: its directory and its group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    /// The directory that holds it.
    pub dir: PathBuf,
    /// The group.
    pub group: u64,
}

/// What [`diff`] compares: two journals, the range and the options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRequest {
    /// The expected journal.
    pub left: Journal,
    /// The journal compared with it.
    pub right: Journal,
    /// The first `group_seq` compared; `None` is the later of the two
    /// journals' first events (or of the events after their checkpoints).
    pub from: Option<u64>,
    /// The last `group_seq` compared. `None` compares up to the end of the
    /// longer complete prefix, not the shorter: when the events both sides
    /// hold are equal and one side has further complete events, the
    /// result is [`Report::Diverged`] with [`Kind::End`] at the first event
    /// the shorter side lacks. A side that stops at a gap or an incomplete
    /// event inside that range makes it [`Report::NotComparable`], whichever
    /// side it is. To compare only the prefix both sides share, give `to`
    /// explicitly, at or below the shorter prefix's end. From a checkpoint
    /// (`from_checkpoint`), the range is the one that checkpoint opened, to
    /// its own end: there a gap or an incomplete event that ends a middle
    /// range ends the comparison, as the end of a complete prefix does,
    /// and both sides must end there.
    pub to: Option<u64>,
    /// Compare journals whose manifests differ; otherwise a manifest
    /// difference is [`Report::NotComparable`].
    pub accept_manifest: bool,
    /// Compare from the event after the left journal's checkpoint with
    /// this id, and the right journal's checkpoint at the same
    /// `group_seq` (A9 section 7), in the range it opens.
    pub from_checkpoint: Option<u64>,
}

/// What differs first. More kinds may be added: a caller's match keeps a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// The event itself.
    InputEvent,
    /// An observation other than an output intent.
    Observation,
    /// An output intent: an offer's or a commit's length and digest.
    OutputIntent,
    /// The left journal has an observation the right one lacks.
    MissingObservation,
    /// The right journal has an observation the left one lacks.
    ExtraObservation,
    /// The event's end.
    End,
    /// A checkpoint of the application's state (A9): its record differs,
    /// or is on one side only.
    StateCheckpoint,
}

impl Kind {
    /// Its name in the output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InputEvent => "input event",
            Self::Observation => "observation",
            Self::OutputIntent => "output intent",
            Self::MissingObservation => "missing observation",
            Self::ExtraObservation => "extra observation",
            Self::End => "end",
            Self::StateCheckpoint => "state checkpoint",
        }
    }
}

/// A diff's result: identical over the compared range, the first
/// difference as `(group_seq, index, kind)`, not comparable (the inputs
/// do not cover the range under the stated basis), or an error. More
/// outcomes may be added: a caller's match keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Report {
    /// Identical over the range.
    Identical {
        /// The first `group_seq` compared.
        from: u64,
        /// The last event compared, if any.
        to: Option<u64>,
        /// The events compared.
        events: u64,
    },
    /// The first difference.
    Diverged {
        /// The event.
        group_seq: u64,
        /// The observation's index, for an observation.
        index: Option<u32>,
        /// What differs.
        kind: Kind,
        /// The left journal's record.
        expected: String,
        /// The right journal's record.
        found: String,
    },
    /// The journals cannot be compared over the range.
    NotComparable {
        /// Why.
        reason: String,
    },
    /// The diff failed.
    Error {
        /// Why.
        reason: String,
    },
}

/// Every reference counts as held: the diff compares records, not the
/// payloads they name.
struct Records;

impl Coverage for Records {
    fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
        Some((u64::MAX, u64::MAX))
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }

    // A checkpoint is compared as its record: the store's bytes are not
    // read, so every recorded checkpoint opens its range.
    fn checkpoint(&self, _position: u64, _end: u64) -> CheckpointHeld {
        CheckpointHeld::Durable
    }
}

/// As [`Records`], with checkpoints as a store opened read only holds
/// them: one it lost never opens its range (`--from-checkpoint`).
struct Stored<'s, D: Disk>(&'s CheckpointStore<D>);

impl<D: Disk> Coverage for Stored<'_, D> {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        Records.positions(recording_id)
    }

    fn ended(&self, recording_id: u64) -> Option<u64> {
        Records.ended(recording_id)
    }

    fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
        self.0.holds(position, end)
    }
}

/// Where a journal opens for the diff.
#[derive(Debug, Clone, Copy)]
enum At {
    /// At its first event.
    Start,
    /// After its checkpoint with this id (the left journal's).
    Id(u64),
    /// After its checkpoint at this `group_seq` (the right journal's).
    GroupSeq(u64),
}

impl At {
    /// Whether `checkpoint` is the one this opens at.
    fn names(self, checkpoint: &CheckpointRecord) -> bool {
        match self {
            Self::Start => false,
            Self::Id(id) => checkpoint.checkpoint_id == id,
            Self::GroupSeq(group_seq) => checkpoint.group_seq == group_seq,
        }
    }
}

/// The checkpoint directory beside a group's journal (A9 section 2).
pub const CHECKPOINTS: &str = "checkpoints";

/// The first checkpoint record in `journal` that `found` accepts.
fn find_checkpoint<D: Disk>(
    journal: &mut GroupJournal<D>,
    found: impl Fn(&CheckpointRecord) -> bool,
) -> Result<Option<CheckpointRecord>, JournalError> {
    let mut checkpoint = None;
    let _ = journal.walk(0, |_, _, record| {
        if let GroupRecord::Checkpoint(recorded) = record
            && found(recorded)
        {
            checkpoint = Some(*recorded);
            return false;
        }
        true
    })?;
    Ok(checkpoint)
}

/// A zeroed buffer for `checkpoint`'s snapshot, one allocation that fails
/// typed; empty for none (the open then says it is unknown).
fn snapshot_buffer(checkpoint: Option<&CheckpointRecord>) -> Result<Vec<u8>, String> {
    let length = checkpoint.map_or(0, |checkpoint| checkpoint.length);
    let length = usize::try_from(length).map_err(|_| format!("a snapshot of {length} bytes"))?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| format!("a snapshot of {length} bytes cannot be allocated"))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

/// A journal open for the diff: its cursor, its header's manifest and
/// first `group_seq`, and the checkpoint it opened at.
struct Opened<D: Disk> {
    cursor: ReplayCursor<ReadOnly<D>>,
    manifest: Vec<u8>,
    first: u64,
    checkpoint: Option<CheckpointRecord>,
}

fn error(reason: impl Into<String>) -> Report {
    Report::Error {
        reason: reason.into(),
    }
}

fn not_comparable(reason: impl Into<String>) -> Report {
    Report::NotComparable {
        reason: reason.into(),
    }
}

/// Opens `journal` on `disk`, read only.
fn open<D: Disk + Clone>(
    disk: D,
    journal: &Journal,
    side: &str,
    at: At,
) -> Result<Opened<D>, Report> {
    let mut disk = ReadOnly(disk);
    let store_disk = disk.clone();
    let context = |what: &dyn std::fmt::Display| {
        error(format!(
            "{side} journal (group {} in {}): {what}",
            journal.group,
            journal.dir.display()
        ))
    };
    let geometry = recorded_geometry(&mut disk, &journal.dir, journal.group)
        .map_err(|failure| context(&failure))?
        .ok_or_else(|| context(&"no journal"))?;
    let segment_length = u32::try_from(geometry.segment_length())
        .map_err(|_| context(&"a segment longer than a journal's"))?;
    let journal_config = JournalConfig::new(segment_length, SyncPolicy::PerSegment);
    let mut recovered = match GroupJournal::recover(
        disk,
        &journal.dir,
        journal.group,
        journal_config,
    ) {
        Ok(recovered) => recovered.journal,
        // Another contract or clock: another journal, not a corrupt one.
        Err(JournalError::Unsupported(header)) => {
            return Err(not_comparable(format!(
                "{side} journal: {}",
                match header {
                    UnsupportedHeader::Contract { found } => {
                        format!(
                            "captured under contract {found}, this build replays {CONTRACT_VERSION}"
                        )
                    }
                    UnsupportedHeader::Clock { found } =>
                        format!("a clock this build does not know ({found})"),
                }
            )));
        }
        Err(failure) => {
            return Err(context(&format_args!(
                "{failure}; the journal needs recovery"
            )));
        }
    };
    // The largest event, so the cursor's buffer is sized by the journal,
    // not by a bound.
    let (mut bytes, mut records, mut largest, mut most) = (0u64, 0usize, 0u64, 0usize);
    let mut too_many = false;
    let _ = recovered
        .walk(0, |position, end, record| {
            if matches!(
                record,
                GroupRecord::Header(_) | GroupRecord::Gap(_) | GroupRecord::Unavailable(_)
            ) {
                return true;
            }
            let grown = end
                .checked_sub(position)
                .and_then(|length| bytes.checked_add(length))
                .zip(records.checked_add(1));
            let Some((grown, counted)) = grown else {
                too_many = true;
                return false;
            };
            (bytes, records) = (grown, counted);
            if matches!(record, GroupRecord::End(_)) {
                largest = largest.max(bytes);
                most = most.max(records);
                (bytes, records) = (0, 0);
            }
            true
        })
        .map_err(|failure| context(&failure))?;
    if too_many || most > MAX_RECORDS {
        return Err(context(&format_args!(
            "an event of more than {MAX_RECORDS} records"
        )));
    }
    let largest = usize::try_from(largest).map_err(|_| context(&"an event past usize"))?;
    let mut header = None;
    let _ = recovered
        .walk(0, |_, _, record| {
            if let GroupRecord::Header(found) = record {
                header = Some((found.manifest.to_vec(), found.first_group_seq));
            }
            false
        })
        .map_err(|failure| context(&failure))?;
    let (manifest, first) = header.ok_or_else(|| context(&"no header"))?;
    let config = ReplayConfig::new(&manifest);
    let room = CursorConfig::new(largest.max(1), most.max(2));
    let opened = match at {
        At::Start => {
            let recovery = recover(&mut recovered, &Records, RECOVERY_CAPACITY)
                .map_err(|failure| context(&failure))?;
            ReplayCursor::open(recovered, &recovery, &config, room).map(|cursor| (cursor, None))
        }
        At::Id(_) | At::GroupSeq(_) => {
            let found = find_checkpoint(&mut recovered, |found| at.names(found))
                .map_err(|failure| context(&failure))?;
            let checkpoint_id = match (found, at) {
                (Some(found), _) => found.checkpoint_id,
                // Unknown: the open says so.
                (None, At::Id(id)) => id,
                (None, At::GroupSeq(group_seq)) => {
                    return Err(not_comparable(format!(
                        "{side} journal: no checkpoint at group_seq {group_seq}"
                    )));
                }
                (None, At::Start) => return Err(context(&"no checkpoint to open at")),
            };
            // The group's checkpoint store, in the checkpoint directory
            // beside its journal (A9 section 2), opened as its recovery
            // would leave it, without repairing it.
            let ended = recorded_end(&mut recovered).map_err(|failure| context(&failure))?;
            let mut store = match CheckpointStore::open_verified(
                store_disk,
                &journal.dir.join(CHECKPOINTS),
                journal.group,
                journal_config,
                ended,
            ) {
                Ok(store) => store,
                // No store, or no directory for it.
                Err(SegmentError::NotFound { .. }) => {
                    return Err(not_comparable(format!(
                        "{side} journal: checkpoint {checkpoint_id}'s store is not there"
                    )));
                }
                Err(SegmentError::Io(failure))
                    if failure.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Err(not_comparable(format!(
                        "{side} journal: checkpoint {checkpoint_id}'s store is not there"
                    )));
                }
                Err(failure) => return Err(context(&failure)),
            };
            // Which ranges recover depends on the group's reopen hold:
            // recovery takes the header's (A9-5); RECOVERY_CAPACITY only
            // sizes the tracker's queues. Every range is derived, a middle
            // one too.
            let (recovery, ranges) =
                recover_ranges(&mut recovered, &Stored(&store), RECOVERY_CAPACITY)
                    .map_err(|failure| context(&failure))?;
            // A checkpoint the store does not hold is not comparable, before
            // its snapshot's buffer is reserved.
            if let Some(found) = found
                && !matches!(
                    found.end().map(|end| store.holds(found.position, end)),
                    Some(CheckpointHeld::Durable | CheckpointHeld::Written)
                )
            {
                return Err(not_comparable(format!(
                    "{side} journal: checkpoint {checkpoint_id}'s snapshot is lost or corrupt"
                )));
            }
            let mut snapshot =
                snapshot_buffer(found.as_ref()).map_err(|failure| context(&failure))?;
            ReplayCursor::open_at_checkpoint(
                recovered,
                &recovery,
                &ranges,
                &mut store,
                checkpoint_id,
                &config,
                room,
                &mut snapshot,
            )
            .map(|(cursor, checkpoint)| (cursor, Some(checkpoint)))
        }
    };
    let (cursor, checkpoint) = match opened {
        Ok(opened) => opened,
        Err(ReplayError::Header(mismatch)) => {
            return Err(not_comparable(format!("{side} journal: {mismatch}")));
        }
        Err(
            failure @ (ReplayError::UnknownCheckpoint { .. }
            | ReplayError::NotInPrefix { .. }
            | ReplayError::CheckpointCorrupt { .. }),
        ) => return Err(not_comparable(format!("{side} journal: {failure}"))),
        Err(failure) => return Err(context(&failure)),
    };
    Ok(Opened {
        cursor,
        manifest,
        first,
        checkpoint,
    })
}

/// Compares the journals `args` names on the operating system's files.
///
/// The result is [`Report::Identical`] only over the same complete
/// comparable range of both journals; an input shorter than the range, a
/// gap, a corrupt or unsupported record, or a missing checkpoint is
/// [`Report::NotComparable`] or [`Report::Error`], never `Identical`.
#[must_use]
pub fn diff(args: &DiffRequest) -> Report {
    diff_on(crate::disk::StdDisk, args)
}

/// Compares the journals `args` names on `disk`.
#[must_use]
pub fn diff_on<D: Disk + Clone>(disk: D, args: &DiffRequest) -> Report {
    let at = args.from_checkpoint.map_or(At::Start, At::Id);
    let mut left = match open(disk.clone(), &args.left, "left", at) {
        Ok(left) => left,
        Err(report) => return report,
    };
    // The id names the left journal's checkpoint; the right journal's is
    // the one at the same `group_seq`.
    let at = left
        .checkpoint
        .map_or(At::Start, |checkpoint| At::GroupSeq(checkpoint.group_seq));
    let mut right = match open(disk, &args.right, "right", at) {
        Ok(right) => right,
        Err(report) => return report,
    };
    if !args.accept_manifest && left.manifest != right.manifest {
        return not_comparable("the manifests differ (--accept-manifest compares them)");
    }
    // From a checkpoint, the first event compared is the one after it,
    // and the two checkpoints are compared first, as records.
    let (left_first, right_first) = match (left.checkpoint, right.checkpoint) {
        (Some(left_checkpoint), Some(right_checkpoint)) => {
            let range = Range {
                from: 0,
                to: None,
                explicit_from: false,
                to_range_end: false,
            };
            if let Some(report) =
                compare_checkpoints(&[left_checkpoint], &[right_checkpoint], range)
            {
                return report;
            }
            let after = |checkpoint: CheckpointRecord| checkpoint.group_seq.checked_add(1);
            match (after(left_checkpoint), after(right_checkpoint)) {
                (Some(left), Some(right)) => (left, right),
                _ => return error("a checkpoint at the last group_seq"),
            }
        }
        _ => (left.first, right.first),
    };
    let first = left_first.max(right_first);
    let from = args.from.unwrap_or(first);
    // Below a journal's first event, its events are not there to compare.
    if from < first {
        let what = if left.checkpoint.is_some() {
            "the event after the checkpoint"
        } else {
            "a journal's first event"
        };
        return not_comparable(format!("--from {from} is before {what}, group_seq {first}"));
    }
    compare(
        &mut left.cursor,
        &mut right.cursor,
        Range {
            from,
            to: args.to,
            explicit_from: args.from.is_some(),
            to_range_end: left.checkpoint.is_some(),
        },
    )
}

/// One side's next item in the range.
enum Item<'c> {
    Event(ReplayEvent<'c>),
    Stop(Stop),
}

/// The next event at or past `from`, or the stop.
fn next_from<'c, D: Disk>(
    cursor: &'c mut ReplayCursor<D>,
    from: u64,
    side: &str,
    checkpoints: &mut Vec<CheckpointRecord>,
) -> Result<Item<'c>, Report> {
    // The checkpoints due after the events already read come first, kept
    // to be compared by `group_seq` (A9 section 7).
    loop {
        match cursor.due_checkpoint() {
            Ok(Some(checkpoint)) => checkpoints.push(checkpoint),
            Ok(None) => break,
            Err(failure) => return Err(error(format!("{side} journal: {failure}"))),
        }
    }
    // With the due ones taken, a step gives no checkpoint: the events it
    // skips below `from` make only checkpoints below it due, which it
    // skips too.
    match cursor.step_from(from) {
        Ok(Step::Event(event)) => Ok(Item::Event(event)),
        Ok(Step::Stop(stop)) => Ok(Item::Stop(stop)),
        Ok(Step::Checkpoint(checkpoint)) => Err(error(format!(
            "{side} journal: checkpoint {} out of order",
            checkpoint.checkpoint_id
        ))),
        Err(failure) => Err(error(format!("{side} journal: {failure}"))),
    }
}

/// A checkpoint record as the output shows it.
fn describe_checkpoint(checkpoint: Option<&CheckpointRecord>) -> String {
    checkpoint.map_or_else(
        || "none".to_owned(),
        |checkpoint| {
            format!(
                "checkpoint {} at group_seq {}, length {}, crc32c {:#010x}, format {}",
                checkpoint.checkpoint_id,
                checkpoint.group_seq,
                checkpoint.length,
                checkpoint.crc32c,
                checkpoint.format
            )
        },
    )
}

/// The first difference between the two sides' checkpoints in the range,
/// matched by `group_seq` in order: a checkpoint is compared as a record,
/// by its `length`, `crc32c` and `format` (its `position` is where each
/// store holds it, and a capture's is none).
fn compare_checkpoints(
    left: &[CheckpointRecord],
    right: &[CheckpointRecord],
    range: Range,
) -> Option<Report> {
    let in_range = |checkpoint: &&CheckpointRecord| {
        checkpoint.group_seq >= range.from && range.to.is_none_or(|to| checkpoint.group_seq <= to)
    };
    let mut left = left.iter().filter(in_range);
    let mut right = right.iter().filter(in_range);
    loop {
        let (expected, found) = match (left.next(), right.next()) {
            (None, None) => return None,
            (Some(expected), Some(found))
                if expected.group_seq == found.group_seq
                    && (expected.length, expected.crc32c, expected.format)
                        == (found.length, found.crc32c, found.format) =>
            {
                continue;
            }
            // A checkpoint at another event, or on one side only: the
            // earlier one is the difference.
            (Some(expected), Some(found)) if expected.group_seq < found.group_seq => {
                (Some(expected), None)
            }
            (Some(expected), Some(found)) if found.group_seq < expected.group_seq => {
                (None, Some(found))
            }
            pair => pair,
        };
        let group_seq = expected
            .or(found)
            .map_or(0, |checkpoint| checkpoint.group_seq);
        return Some(Report::Diverged {
            group_seq,
            index: None,
            kind: Kind::StateCheckpoint,
            expected: describe_checkpoint(expected),
            found: describe_checkpoint(found),
        });
    }
}

/// Bytes as the output shows them: their length and digest, never the
/// bytes themselves.
fn bytes(bytes: &[u8]) -> String {
    format!(
        "length {}, crc32c {:#010x}",
        bytes.len(),
        crate::crc32c::crc32c(bytes)
    )
}

/// Describes `record` for the output: its fields, with any payload or
/// value as its length and digest.
fn describe(record: Option<&GroupRecord<'_>>) -> String {
    match record {
        None => "none".to_owned(),
        Some(GroupRecord::Outcome(outcome)) => {
            let operation = match outcome.operation {
                Operation::Offer => "offer",
                Operation::Claim => "claim",
                Operation::Commit => "commit",
            };
            format!(
                "{operation}, stream {} session {}, length {}, crc32c {:#010x}, {:?}",
                outcome.stream_id,
                outcome.session_id,
                outcome.length,
                outcome.crc32c,
                outcome.outcome
            )
        }
        Some(GroupRecord::Message(message)) => {
            let payload = match message.payload {
                Payload::Inline(inline) => format!("inline, {}", bytes(inline)),
                Payload::Reference {
                    recording_id,
                    length,
                } => format!("by reference to recording {recording_id}, length {length}"),
                Payload::Unavailable { length } => format!("not captured, length {length}"),
            };
            let extension = message
                .extension
                .map_or_else(|| "none".to_owned(), |extension| bytes(extension));
            format!(
                "message {}, logical time {}, incarnation {}, stream {} session {} lane {}, \
                 position {}, extent {}, reserved {}, end of stream {}, extension {extension}, \
                 payload {payload}",
                message.group_seq,
                message.logical_time,
                message.incarnation,
                message.stream_id,
                message.session_id,
                message.lane.get(),
                message.position,
                message.extent,
                message.reserved_value,
                message.end_of_stream
            )
        }
        Some(GroupRecord::Conflated(view)) => format!(
            "conflated {}, logical time {}, stream {} session {}, key {}, version {}, {:?}, \
             value {}",
            view.group_seq,
            view.logical_time,
            view.stream_id,
            view.session_id,
            view.key,
            view.version,
            view.freshness,
            bytes(view.value)
        ),
        Some(GroupRecord::External(external)) => format!(
            "external {}, logical time {}, kind {}, value {}",
            external.group_seq,
            external.logical_time,
            external.kind,
            bytes(external.value)
        ),
        Some(GroupRecord::ExternalObservation(observation)) => format!(
            "external value, kind {}, {}",
            observation.kind,
            bytes(observation.value)
        ),
        Some(record) => format!("{record:?}"),
    }
}

/// Why an event in the range cannot be compared, if it cannot.
fn uncomparable(event: &ReplayEvent<'_>, side: &str) -> Option<String> {
    let seq = event.group_seq();
    if event.reference_unavailable() {
        return Some(format!(
            "{side} journal: event {seq}'s reference is unavailable"
        ));
    }
    match event.record(0) {
        Some(Ok(record)) if matches!(record.role(), Role::Uncaptured(_)) => Some(format!(
            "{side} journal: event {seq}'s payload was not captured"
        )),
        _ => None,
    }
}

/// Why a stop inside the range makes it not comparable.
fn stopped(stop: Stop, side: &str) -> String {
    match stop {
        Stop::Gap(gap) => format!(
            "{side} journal: a gap marker from group_seq {} to {}",
            gap.from_seq, gap.to_seq
        ),
        Stop::Incomplete { group_seq } => {
            format!("{side} journal: event {group_seq} ended incomplete")
        }
        Stop::EndOfPrefix {
            complete_recording_seq,
        } => format!(
            "the range is past the {side} journal's complete prefix, which ends at \
             group_seq {complete_recording_seq}"
        ),
    }
}

/// The first event a stop leaves out: `None` past `u64`.
fn first_missing(stop: &Stop) -> Option<u64> {
    match *stop {
        Stop::Gap(gap) => Some(gap.from_seq),
        Stop::Incomplete { group_seq } => Some(group_seq),
        Stop::EndOfPrefix {
            complete_recording_seq,
        } => complete_recording_seq.checked_add(1),
    }
}

/// The range compared: `--from` (given or the default) and `--to`.
#[derive(Debug, Clone, Copy)]
struct Range {
    from: u64,
    to: Option<u64>,
    /// `--from` was given: a range that starts at a prefix's first event
    /// left out is past it. The default `--from` is the journals' own
    /// first event, so an empty journal there is the `end` kind instead.
    explicit_from: bool,
    /// From a checkpoint: the range the checkpoint opened is compared to
    /// its end, and the stop that ends it (a gap or an incomplete event,
    /// for a middle range) ends the comparison as the end of a complete
    /// prefix does. Both sides must end there. A `--to` past that stop
    /// still makes it not comparable: the stops' own checks against `to`
    /// say so.
    to_range_end: bool,
}

impl Range {
    /// Whether a range starting at `from` begins past a prefix whose first
    /// event left out is `missing`.
    const fn starts_past(&self, missing: u64) -> bool {
        missing < self.from || (self.explicit_from && missing == self.from)
    }
}

/// One side's state at a step: an event in the range, the range's end
/// on that side (an event past `to`), or a stop.
enum Side<'c> {
    Event(ReplayEvent<'c>),
    Past,
    Stop(Stop),
}

fn side<'c>(item: Item<'c>, to: Option<u64>) -> Side<'c> {
    match item {
        Item::Event(event) if event.incomplete() => Side::Stop(Stop::Incomplete {
            group_seq: event.group_seq(),
        }),
        Item::Event(event) if to.is_some_and(|to| event.group_seq() > to) => Side::Past,
        Item::Event(event) => Side::Event(event),
        Item::Stop(stop) => Side::Stop(stop),
    }
}

/// Compares two cursors' events from `from` to `to`, or, without `to`, to
/// the end of the longer complete prefix (section 10 as built): records
/// on one side only are the `end` kind, unless that side stopped at a gap
/// or an incomplete event, which is not comparable; so is a range past
/// either complete prefix.
fn compare<L: Disk, R: Disk>(
    left: &mut ReplayCursor<L>,
    right: &mut ReplayCursor<R>,
    range: Range,
) -> Report {
    let Range { from, to, .. } = range;
    if let Some(to) = to
        && to < from
    {
        return not_comparable(format!("the range from {from} to {to} is empty"));
    }
    let mut events = 0u64;
    let mut last = None;
    let (mut left_checkpoints, mut right_checkpoints) = (Vec::new(), Vec::new());
    loop {
        let left_side = match next_from(left, from, "left", &mut left_checkpoints) {
            Ok(item) => side(item, to),
            Err(report) => return report,
        };
        let right_side = match next_from(right, from, "right", &mut right_checkpoints) {
            Ok(item) => side(item, to),
            Err(report) => return report,
        };
        // The checkpoints after the events compared so far.
        if let Some(report) = compare_checkpoints(&left_checkpoints, &right_checkpoints, range) {
            return report;
        }
        left_checkpoints.clear();
        right_checkpoints.clear();
        let identical = Report::Identical {
            from,
            to: last,
            events,
        };
        // A gap or an incomplete event inside the range is not comparable,
        // the left side first.
        let inside = |stop: &Stop| {
            !range.to_range_end
                && !matches!(stop, Stop::EndOfPrefix { .. })
                && first_missing(stop).is_some_and(|seq| to.is_none_or(|to| seq <= to))
        };
        for (stopped_side, name) in [(&left_side, "left"), (&right_side, "right")] {
            if let Side::Stop(stop) = stopped_side
                && inside(stop)
            {
                return not_comparable(stopped(*stop, name));
            }
        }
        match (left_side, right_side) {
            (Side::Event(left_event), Side::Event(right_event)) => {
                if let Some(reason) = uncomparable(&left_event, "left")
                    .or_else(|| uncomparable(&right_event, "right"))
                {
                    return not_comparable(reason);
                }
                if let Some(report) = compare_events(&left_event, &right_event) {
                    return report;
                }
                events = match events.checked_add(1) {
                    Some(events) => events,
                    None => return error("more events than a u64 counts"),
                };
                last = Some(left_event.group_seq());
            }
            // One side has an event in the range, the other's next event is
            // past it: the event is missing there.
            // The one-sided event is checked for comparability first, as
            // a pair is: one that is not comparable makes the range so,
            // never a divergence.
            (Side::Event(event), Side::Past) => {
                if let Some(reason) = uncomparable(&event, "left") {
                    return not_comparable(reason);
                }
                return one_sided(&event, "right");
            }
            (Side::Past, Side::Event(event)) => {
                if let Some(reason) = uncomparable(&event, "right") {
                    return not_comparable(reason);
                }
                return one_sided(&event, "left");
            }
            (Side::Event(event), Side::Stop(stop)) => {
                if let Some(report) = past_start(stop, range, "right") {
                    return report;
                }
                if let Some(reason) = uncomparable(&event, "left") {
                    return not_comparable(reason);
                }
                return ended_one_side(&event, stop, "right");
            }
            (Side::Stop(stop), Side::Event(event)) => {
                if let Some(report) = past_start(stop, range, "left") {
                    return report;
                }
                if let Some(reason) = uncomparable(&event, "right") {
                    return not_comparable(reason);
                }
                return ended_one_side(&event, stop, "left");
            }
            // Both sides ended, or are past the range.
            (left_end, right_end) => {
                for (end, name) in [(left_end, "left"), (right_end, "right")] {
                    let Side::Stop(stop) = end else {
                        continue;
                    };
                    let missing = first_missing(&stop);
                    // A range that names events past this prefix.
                    if let (Some(to), Some(missing)) = (to, missing)
                        && missing <= to
                    {
                        return not_comparable(stopped(stop, name));
                    }
                    if events == 0 && missing.is_some_and(|missing| range.starts_past(missing)) {
                        return not_comparable(format!(
                            "--from {from} is past the {name} journal's complete prefix, \
                             which ends at group_seq {}",
                            missing
                                .and_then(|missing| missing.checked_sub(1))
                                .unwrap_or(0)
                        ));
                    }
                }
                return identical;
            }
        }
    }
}

/// A range past the `side` journal's complete prefix, which ended at
/// `stop`: one that starts past it, or an explicit end that names events
/// past it. Not comparable.
fn past_start(stop: Stop, range: Range, side: &str) -> Option<Report> {
    let Range { from, to, .. } = range;
    let missing = first_missing(&stop)?;
    if to.is_some_and(|to| missing <= to) {
        return Some(not_comparable(stopped(stop, side)));
    }
    range.starts_past(missing).then(|| {
        not_comparable(format!(
            "--from {from} is past the {side} journal's complete prefix, whose first \
             event left out is group_seq {missing}"
        ))
    })
}

/// `event` is on one side only, and the `missing` side's next event is
/// past the range.
fn one_sided(event: &ReplayEvent<'_>, missing: &str) -> Report {
    let record = describe(decoded(event, 0).as_ref());
    let none = format!("none (the {missing} journal's next event is past the range)");
    let (expected, found) = if missing == "left" {
        (none, record)
    } else {
        (record, none)
    };
    Report::Diverged {
        group_seq: event.group_seq(),
        index: None,
        kind: Kind::InputEvent,
        expected,
        found,
    }
}

/// The records of `event` are on one side only: the other side's complete
/// prefix ended at `stop`.
fn ended_one_side(event: &ReplayEvent<'_>, stop: Stop, ended: &str) -> Report {
    let record = describe(decoded(event, 0).as_ref());
    let none = match stop {
        Stop::EndOfPrefix {
            complete_recording_seq,
        } => format!(
            "none (the {ended} journal's complete prefix ends at group_seq {complete_recording_seq})"
        ),
        stop => format!("none ({})", stopped(stop, ended)),
    };
    let (expected, found) = if ended == "left" {
        (none, record)
    } else {
        (record, none)
    };
    Report::Diverged {
        group_seq: event.group_seq(),
        index: None,
        kind: Kind::End,
        expected,
        found,
    }
}

/// Record `index` of `event`, decoded.
fn decoded<'c>(event: &ReplayEvent<'c>, index: usize) -> Option<GroupRecord<'c>> {
    event.record(index).and_then(Result::ok)
}

/// The first difference between two events, if any.
///
/// Every recorded field takes part: nothing is excluded at compare time,
/// and the trace extension is an input like any other (karyos#675). An
/// offer is compared by its length and CRC32C digest, the version 1
/// record (recording-group-replay.md §5); a stronger digest would need a
/// version 2 record (ADR-0077, ADR-0051).
fn compare_events(left: &ReplayEvent<'_>, right: &ReplayEvent<'_>) -> Option<Report> {
    let diverged = |index: Option<usize>, kind: Kind, at: (Option<usize>, Option<usize>)| {
        Some(Report::Diverged {
            group_seq: left.group_seq(),
            index: index.and_then(|index| u32::try_from(index).ok()),
            kind,
            expected: describe(at.0.and_then(|at| decoded(left, at)).as_ref()),
            found: describe(at.1.and_then(|at| decoded(right, at)).as_ref()),
        })
    };
    if left.record_bytes(0) != right.record_bytes(0) {
        return diverged(None, Kind::InputEvent, (Some(0), Some(0)));
    }
    // Observations are records 1 to len - 2; the end is the last.
    let (Some(left_count), Some(right_count)) =
        (left.len().checked_sub(2), right.len().checked_sub(2))
    else {
        return Some(error("an event of fewer than two records"));
    };
    for index in 0..left_count.min(right_count) {
        let at = index.checked_add(1)?;
        if left.record_bytes(at) == right.record_bytes(at) {
            continue;
        }
        let intent = matches!(
            (decoded(left, at), decoded(right, at)),
            (Some(GroupRecord::Outcome(a)), Some(GroupRecord::Outcome(b)))
                if a.operation == b.operation
                    && matches!(a.operation, Operation::Offer | Operation::Commit)
                    && (a.length, a.crc32c) != (b.length, b.crc32c)
        );
        let kind = if intent {
            Kind::OutputIntent
        } else {
            Kind::Observation
        };
        return diverged(Some(index), kind, (Some(at), Some(at)));
    }
    if left_count > right_count {
        let at = right_count.checked_add(1)?;
        return diverged(
            Some(right_count),
            Kind::MissingObservation,
            (Some(at), None),
        );
    }
    if right_count > left_count {
        let at = left_count.checked_add(1)?;
        return diverged(Some(left_count), Kind::ExtraObservation, (None, Some(at)));
    }
    // The ends agree: their observation counts are the ones compared, and
    // an end that says incomplete is a stop before this.
    None
}
