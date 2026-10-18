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
use karyos_archive::group::journal::{GroupJournal, JournalConfig, JournalError};
use karyos_archive::group::prefix::{Coverage, recover};
use karyos_archive::group::record::{
    CONTRACT_VERSION, GroupRecord, Operation, Payload, Role, UnsupportedHeader,
};
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

/// The records one event may hold, its first, its observations and its
/// end: an event past it is an error (exit 3).
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
            // Any dash but a lone one is an option; none other is known.
            option if option.starts_with('-') && option.len() > 1 => {
                return Err(format!("unknown option {option}"));
            }
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
    let mut recovered = match GroupJournal::recover(disk, &journal.dir, journal.group, config) {
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
    let recovery = recover(&mut recovered, &Records, RECOVERY_CAPACITY)
        .map_err(|failure| context(&failure))?;
    let config = ReplayConfig {
        manifest: &manifest,
        accept_manifest: false,
    };
    let room = CursorConfig {
        bytes: largest.max(1),
        records: most.max(2),
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
    let first = left.first.max(right.first);
    let from = args.from.unwrap_or(first);
    // Below a journal's first event, its events are not there to compare.
    if from < first {
        return not_comparable(format!(
            "--from {from} is before a journal's first event, group_seq {first}"
        ));
    }
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

/// Bytes as the output shows them: their length and digest, never the
/// bytes themselves.
fn bytes(bytes: &[u8]) -> String {
    format!(
        "length {}, crc32c {:#010x}",
        bytes.len(),
        karyos_archive::crc32c::crc32c(bytes)
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
            format!(
                "message {}, stream {} session {} lane {}, position {}, extent {}, \
                 reserved {}, end of stream {}, payload {payload}",
                message.group_seq,
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
            "conflated {}, stream {} session {}, key {}, version {}, {:?}, value {}",
            view.group_seq,
            view.stream_id,
            view.session_id,
            view.key,
            view.version,
            view.freshness,
            bytes(view.value)
        ),
        Some(GroupRecord::External(external)) => format!(
            "external {}, kind {}, value {}",
            external.group_seq,
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
    from: u64,
    to: Option<u64>,
) -> Report {
    if let Some(to) = to
        && to < from
    {
        return not_comparable(format!("the range from {from} to {to} is empty"));
    }
    let mut events = 0u64;
    let mut last = None;
    loop {
        let left_side = match next_from(left, from, "left") {
            Ok(item) => side(item, to),
            Err(report) => return report,
        };
        let right_side = match next_from(right, from, "right") {
            Ok(item) => side(item, to),
            Err(report) => return report,
        };
        let identical = Report::Identical {
            from,
            to: last,
            events,
        };
        // A gap or an incomplete event inside the range is not comparable,
        // the left side first.
        let inside = |stop: &Stop| {
            !matches!(stop, Stop::EndOfPrefix { .. })
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
            (Side::Event(event), Side::Past) => {
                return one_sided(&event, "right");
            }
            (Side::Past, Side::Event(event)) => {
                return one_sided(&event, "left");
            }
            (Side::Event(event), Side::Stop(stop)) => {
                return past_start(stop, from, to, "right")
                    .unwrap_or_else(|| ended_one_side(&event, stop, "right"));
            }
            (Side::Stop(stop), Side::Event(event)) => {
                return past_start(stop, from, to, "left")
                    .unwrap_or_else(|| ended_one_side(&event, stop, "left"));
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
                    if events == 0 && missing.is_some_and(|missing| missing < from) {
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
fn past_start(stop: Stop, from: u64, to: Option<u64>, side: &str) -> Option<Report> {
    let missing = first_missing(&stop)?;
    if to.is_some_and(|to| missing <= to) {
        return Some(not_comparable(stopped(stop, side)));
    }
    (missing < from).then(|| {
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
