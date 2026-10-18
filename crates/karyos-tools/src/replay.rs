// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools replay diff` (`quantstratum-docs:
//! karyos/design/recording-group-replay.md` section 10): the first
//! difference between two recording group journals.
//!
//! It recovers both journals, compares their headers, then their events
//! in order over the range, record by record: the input event, each
//! observation, and the event's end. It reads only. Both journals are
//! recovered through [`ReadOnly`], so one that recovery would repair (a
//! torn tail) is an error, never repaired; it opens no driver.
//!
//! The comparison is of records, never of payload bytes: a payload by
//! reference is compared as its reference, so the complete prefix is
//! bounded only by incomplete events and gap markers. A payload not
//! captured, or a reference unavailable, in the range is not comparable.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use karyos_archive::disk::{Disk, ReadOnly};
use karyos_archive::group::journal::{GroupJournal, JournalConfig};
use karyos_archive::group::prefix::{Coverage, recover};
use karyos_archive::group::record::{GroupRecord, Operation, Role};
use karyos_archive::group::replay::{
    CursorConfig, ReplayConfig, ReplayCursor, ReplayError, ReplayEvent, Step, Stop,
};
use karyos_archive::segment::{SyncPolicy, recorded_geometry};

#[cfg(test)]
mod tests;

/// The usage text of `karyos-tools replay diff --help`.
pub const HELP: &str = "\
karyos-tools replay diff: the first difference between two recording group
journals (recording-group-replay.md section 10). It reads only.

Usage: karyos-tools replay diff <left-dir> <left-group> <right-dir> <right-group>
           [--from <seq>] [--to <seq>] [--json] [--accept-manifest]

  --from <seq>          the first group_seq compared [the first event]
  --to <seq>            the last group_seq compared [the end of the shorter
                        complete prefix]
  --json                one JSON object instead of text
  --accept-manifest     compare journals whose manifests differ
  -h, --help            print this text

Exit status: 0 identical over the range; 1 diverged, the first difference
reported; 2 not comparable; 3 error (arguments, I/O, or a journal that does
not recover read only).
";

/// The events of one event's records an event holds at most: its first,
/// its observations and its end.
const MAX_RECORDS: usize = 16_384;
/// The bytes of one event's records the diff holds at most.
const MAX_BYTES: usize = 64 << 20;
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

/// A `replay diff` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArgs {
    /// The expected journal.
    pub left: Journal,
    /// The journal compared with it.
    pub right: Journal,
    /// The first `group_seq` compared.
    pub from: Option<u64>,
    /// The last `group_seq` compared.
    pub to: Option<u64>,
    /// JSON output.
    pub json: bool,
    /// Compare journals whose manifests differ.
    pub accept_manifest: bool,
}

/// Parses `replay diff`'s arguments, those after `replay diff`: `None`
/// for `--help`.
///
/// # Errors
///
/// What is wrong with them.
pub fn parse_diff(args: impl IntoIterator<Item = OsString>) -> Result<Option<DiffArgs>, String> {
    let mut positional = Vec::new();
    let (mut from, mut to, mut json, mut accept_manifest) = (None, None, false, false);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| format!("not UTF-8: {}", arg.to_string_lossy()))?;
        match text {
            "-h" | "--help" => return Ok(None),
            "--json" => json = true,
            "--accept-manifest" => accept_manifest = true,
            "--from" | "--to" => {
                let value = args
                    .next()
                    .and_then(|value| value.to_str().map(str::to_owned))
                    .ok_or_else(|| format!("{text} needs a group_seq"))?;
                let seq = value
                    .parse::<u64>()
                    .map_err(|_| format!("{text}: not a group_seq: {value}"))?;
                if text == "--from" {
                    from = Some(seq);
                } else {
                    to = Some(seq);
                }
            }
            option if option.starts_with("--") => return Err(format!("unknown option {option}")),
            _ => positional.push(text.to_owned()),
        }
    }
    let [left_dir, left_group, right_dir, right_group] = <[String; 4]>::try_from(positional)
        .map_err(|found| {
            format!(
                "four arguments needed (two directories and their groups), found {}",
                found.len()
            )
        })?;
    let group = |text: &str| {
        text.parse::<u64>()
            .map_err(|_| format!("not a group id: {text}"))
    };
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(format!("--from {from} is past --to {to}"));
    }
    Ok(Some(DiffArgs {
        left: Journal {
            dir: PathBuf::from(left_dir),
            group: group(&left_group)?,
        },
        right: Journal {
            dir: PathBuf::from(right_dir),
            group: group(&right_group)?,
        },
        from,
        to,
        json,
        accept_manifest,
    }))
}

/// What differs first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        }
    }
}

/// A diff's result.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Report {
    /// The exit status: 0, 1, 2 or 3.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Identical { .. } => 0,
            Self::Diverged { .. } => 1,
            Self::NotComparable { .. } => 2,
            Self::Error { .. } => 3,
        }
    }

    /// The text output.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Identical {
                from,
                to: Some(to),
                events,
            } => format!("identical: group_seq {from} to {to}, {events} events\n"),
            Self::Identical { from, to: None, .. } => {
                format!("identical: no events from group_seq {from}\n")
            }
            Self::Diverged {
                group_seq,
                index,
                kind,
                expected,
                found,
            } => {
                let mut out = format!("diverged at group_seq {group_seq}");
                if let Some(index) = index {
                    let _ = write!(out, ", observation {index}");
                }
                let _ = write!(
                    out,
                    ": {}\n  expected: {expected}\n  found:    {found}\n",
                    kind.name()
                );
                out
            }
            Self::NotComparable { reason } => format!("not comparable: {reason}\n"),
            Self::Error { reason } => format!("error: {reason}\n"),
        }
    }

    /// The `--json` output: one object.
    #[must_use]
    pub fn json(&self) -> String {
        let null = || "null".to_owned();
        let (result, group_seq, index, kind, expected, found, reason) = match self {
            Self::Identical { .. } => ("identical", null(), null(), null(), null(), null(), null()),
            Self::Diverged {
                group_seq,
                index,
                kind,
                expected,
                found,
            } => (
                "diverged",
                group_seq.to_string(),
                index.map_or_else(null, |index| index.to_string()),
                quoted(kind.name()),
                quoted(expected),
                quoted(found),
                null(),
            ),
            Self::NotComparable { reason } => (
                "not_comparable",
                null(),
                null(),
                null(),
                null(),
                null(),
                quoted(reason),
            ),
            Self::Error { reason } => (
                "error",
                null(),
                null(),
                null(),
                null(),
                null(),
                quoted(reason),
            ),
        };
        let mut out = format!(
            "{{\"result\":\"{result}\",\"group_seq\":{group_seq},\"index\":{index},\
             \"kind\":{kind},\"expected\":{expected},\"found\":{found},\"reason\":{reason}"
        );
        if let Self::Identical { from, to, events } = self {
            let to = to.map_or_else(null, |to| to.to_string());
            let _ = write!(out, ",\"from\":{from},\"to\":{to},\"events\":{events}");
        }
        out.push_str("}\n");
        out
    }
}

/// `text` as a JSON string.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
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
}

/// A journal open for the diff: its cursor, its header's manifest and
/// first `group_seq`.
struct Opened<D: Disk> {
    cursor: ReplayCursor<ReadOnly<D>>,
    manifest: Vec<u8>,
    first: u64,
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
fn open<D: Disk>(disk: D, journal: &Journal, side: &str) -> Result<Opened<D>, Report> {
    let mut disk = ReadOnly(disk);
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
    let config = JournalConfig {
        segment_length,
        policy: SyncPolicy::PerSegment,
    };
    let mut recovered = GroupJournal::recover(disk, &journal.dir, journal.group, config)
        .map_err(|failure| context(&format_args!("{failure}; the journal needs recovery")))?
        .journal;
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
    let recovery = recover(&mut recovered, &Records, RECOVERY_CAPACITY)
        .map_err(|failure| context(&failure))?;
    let config = ReplayConfig {
        manifest: &manifest,
        accept_manifest: false,
    };
    let room = CursorConfig {
        bytes: MAX_BYTES,
        records: MAX_RECORDS,
    };
    let cursor = match ReplayCursor::open(recovered, &recovery, &config, room) {
        Ok(cursor) => cursor,
        Err(ReplayError::Header(mismatch)) => {
            return Err(not_comparable(format!("{side} journal: {mismatch}")));
        }
        Err(failure) => return Err(context(&failure)),
    };
    Ok(Opened {
        cursor,
        manifest,
        first,
    })
}

/// Compares the journals `args` names on the operating system's files.
#[must_use]
pub fn diff(args: &DiffArgs) -> Report {
    diff_on(karyos_archive::disk::StdDisk, args)
}

/// Compares the journals `args` names on `disk`.
#[must_use]
pub fn diff_on<D: Disk + Clone>(disk: D, args: &DiffArgs) -> Report {
    let mut left = match open(disk.clone(), &args.left, "left") {
        Ok(left) => left,
        Err(report) => return report,
    };
    let mut right = match open(disk, &args.right, "right") {
        Ok(right) => right,
        Err(report) => return report,
    };
    if !args.accept_manifest && left.manifest != right.manifest {
        return not_comparable("the manifests differ (--accept-manifest compares them)");
    }
    let from = args.from.unwrap_or(left.first.max(right.first));
    compare(&mut left.cursor, &mut right.cursor, from, args.to)
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
) -> Result<Item<'c>, Report> {
    match cursor.step_from(from) {
        Ok(Step::Event(event)) => Ok(Item::Event(event)),
        Ok(Step::Stop(stop)) => Ok(Item::Stop(stop)),
        Err(failure) => Err(error(format!("{side} journal: {failure}"))),
    }
}

/// Describes `record` for the output.
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
                "{operation}, stream {} session {}, {:?}, length {}, crc32c {:#010x}",
                outcome.stream_id,
                outcome.session_id,
                outcome.outcome,
                outcome.length,
                outcome.crc32c
            )
        }
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

/// An item as a stop: an incomplete event is outside the complete prefix,
/// so the comparison stops there.
fn as_stop(item: &Item<'_>) -> Option<Stop> {
    match item {
        Item::Stop(stop) => Some(*stop),
        Item::Event(event) if event.incomplete() => Some(Stop::Incomplete {
            group_seq: event.group_seq(),
        }),
        Item::Event(_) => None,
    }
}

/// Compares two cursors' events from `from` to `to`. Without `to`, the
/// range ends where either complete prefix does; with it, a prefix that
/// ends before it is not comparable.
fn compare<L: Disk, R: Disk>(
    left: &mut ReplayCursor<L>,
    right: &mut ReplayCursor<R>,
    from: u64,
    to: Option<u64>,
) -> Report {
    let mut events = 0u64;
    let mut last = None;
    loop {
        let left_item = match next_from(left, from, "left") {
            Ok(item) => item,
            Err(report) => return report,
        };
        let right_item = match next_from(right, from, "right") {
            Ok(item) => item,
            Err(report) => return report,
        };
        let identical = Report::Identical {
            from,
            to: last,
            events,
        };
        let past_to = |item: &Item<'_>| match item {
            Item::Event(event) => to.is_some_and(|to| event.group_seq() > to),
            Item::Stop(_) => false,
        };
        // Both past the range's end: done.
        if past_to(&left_item) && past_to(&right_item) {
            return identical;
        }
        let (left_stop, right_stop) = (as_stop(&left_item), as_stop(&right_item));
        if left_stop.is_some() || right_stop.is_some() {
            let Some(to) = to else {
                return identical;
            };
            // A stop inside the range: the first event it leaves out is at
            // or before `to`.
            let inside = |stop: &Stop| first_missing(stop).is_some_and(|seq| seq <= to);
            return match (left_stop, right_stop) {
                (Some(stop), _) if inside(&stop) => not_comparable(stopped(stop, "left")),
                (_, Some(stop)) if inside(&stop) => not_comparable(stopped(stop, "right")),
                _ => identical,
            };
        }
        let (Item::Event(left_event), Item::Event(right_event)) = (left_item, right_item) else {
            return error("an event without its pair");
        };
        if let Some(reason) =
            uncomparable(&left_event, "left").or_else(|| uncomparable(&right_event, "right"))
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
}

/// Record `index` of `event`, decoded.
fn decoded<'c>(event: &ReplayEvent<'c>, index: usize) -> Option<GroupRecord<'c>> {
    event.record(index).and_then(Result::ok)
}

/// The first difference between two events, if any.
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
    let (left_end, right_end) = (left.len().checked_sub(1)?, right.len().checked_sub(1)?);
    if left.record_bytes(left_end) != right.record_bytes(right_end) {
        return diverged(None, Kind::End, (Some(left_end), Some(right_end)));
    }
    None
}
