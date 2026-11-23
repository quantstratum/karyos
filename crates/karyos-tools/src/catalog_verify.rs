// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog verify` (quantstratum-docs: karyos/SPEC.md §8.4,
//! "Verification"; karyos#665): the per-range integrity outcomes of an
//! archive directory, read only and offline.
//!
//! The logic is [`karyos_archive::integrity::verify`]; this module gathers
//! its evidence from the directory and prints the report. The trust is
//! supplied outside the export, in a trust file:
//!
//! ```text
//! # comments and blank lines are ignored
//! archive <64 hex digits>     the Archive's identity
//! authority <64 hex digits>   an authority public key (one or more)
//! journal <id>                the journal's identity (default 0)
//! time-journal <id>           the time evidence journal's identity, another
//!                             than the journal's; required to verify or
//!                             sign time evidence, never guessed
//! local <64 hex digits>       a store on this host, never external
//! anchors <64 hex digits>     an Archive this one anchors (circular)
//! ```
//!
//! Without `--trust`, every sealed range is `inconsistent` with reason
//! `untrusted_evidence`. Each `--anchors LOCATION=DIR` adds the operator
//! export store in DIR, which the operator identifies by its location
//! digest outside the export: an anchor counts only if it names that
//! location. Exit status: 0 when nothing is inconsistent, 1 when a range,
//! the journal or the copy catalog is, 2 for an error, including a report
//! that could not be written.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;

use karyos_archive::catalog::{CatalogError, list};
use karyos_archive::disk::{Disk as _, ReadOnly, StdDisk};
use karyos_archive::integrity::SealRecord;
use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH, Externality, StoredAnchors};
use karyos_archive::integrity::copies::{
    COPIES_FILE, COPY_RECORD_LENGTH, CopyRecord, CopyState, Enforcement, replay_current,
};
use karyos_archive::integrity::journal::{IntegrityError, read_records};
use karyos_archive::integrity::ledger::read_entries;
use karyos_archive::integrity::time::{self, Requirement, Verdict};
use karyos_archive::integrity::time_evidence;
use karyos_archive::integrity::trust::{
    Custody, HEADS_FILE, KEYS_FILE, PUBLIC_KEY_LENGTH, REGISTRY_ENTRY_LENGTH, SIGNED_HEAD_LENGTH,
    TrustRoot,
};
use karyos_archive::integrity::verify::{Evidence, Outcome, RangeBytes, Verification, verify};
use karyos_archive::segment::{SegmentError, SegmentStore, SyncPolicy, recorded_geometry};

use crate::catalog::EXIT_ERROR;

/// Exit status when a range is inconsistent.
pub const EXIT_INCONSISTENT: u8 = 1;

/// The usage text of `karyos-catalog verify --help`.
pub const HELP: &str = "\
karyos-catalog verify: the integrity of an Archive's recordings (SPEC.md
section 8.4).

Usage: karyos-catalog verify <dir> [--trust FILE] [--anchors HEX=DIR]...
                             [--json]

  verify <dir>   recompute every sealed range's digest, walk the chain,
                 check the signed heads under the trust file and compare
                 with the anchors; read only. Each range is reported
                 verified, beyond_anchor, unsealed, purged or
                 inconsistent, with its reasons. Only verified supports a
                 tamper-evidence statement; every other outcome is
                 unverifiable (C-EXTRACT)
  --trust FILE   the trust supplied outside the export: lines
                 `archive HEX`, `authority HEX`, `journal N`,
                 `time-journal N`, `local HEX`, `anchors HEX`; without
                 it nothing is trusted
  --anchors HEX=DIR
                 an operator export store of anchors (DIR/anchors.kya)
                 at the location HEX (64 hex digits), stated by the
                 operator; repeatable
  --time-requirement NS:GRAN
                 report the time verdict of the entries in
                 <dir>/time-evidence against this requirement: a maximum
                 divergence from UTC of NS nanoseconds and a granularity
                 of GRAN nanoseconds or finer (SPEC.md 8.4); without it
                 no time verdict is reported
  --time-anchors HEX=DIR
                 an operator export store of the anchors of
                 <dir>/time-evidence's own journal, as --anchors;
                 repeatable; required with --time-requirement, since
                 that journal has its own anchor store
  --json         one JSON object instead of text
  -h, --help     print this text

Exit status: 0 nothing inconsistent; 1 a range, the journal or the copy
catalog inconsistent; 2 an error, or a report that could not be written.
";

/// A parsed `verify` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    /// The archive directory.
    pub dir: PathBuf,
    /// The trust file.
    pub trust: Option<PathBuf>,
    /// The operator export anchor stores: each one's location, as the
    /// operator states it, and its directory.
    pub anchors: Vec<([u8; 32], PathBuf)>,
    /// JSON output.
    pub json: bool,
    /// The operator's time requirement; `None` reports no time verdict
    /// (karyos#1065).
    pub time_requirement: Option<Requirement>,
    /// The anchor stores of the entries' own journal, required with a
    /// time requirement.
    pub time_anchors: Vec<([u8; 32], PathBuf)>,
}

/// A command line `verify` refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UsageError {
    /// `--trust` with no file after it.
    #[error("--trust needs a file")]
    TrustNeedsFile,
    /// `--trust` given more than once.
    #[error("--trust given twice")]
    TrustTwice,
    /// `--anchors` with no value after it.
    #[error("--anchors needs HEX=DIR")]
    AnchorsNeedsValue,
    /// An `--anchors` value that is not text.
    #[error("--anchors HEX=DIR is not text")]
    AnchorsNotText,
    /// An `--anchors` value with no `=`.
    #[error("--anchors needs HEX=DIR: the store's location, then its directory")]
    AnchorsNoSeparator,
    /// An `--anchors` location that is not 64 hex digits.
    #[error(transparent)]
    AnchorsLocation(HexError),
    /// An unknown option.
    #[error("unknown option {0}")]
    UnknownOption(String),
    /// More than one directory.
    #[error("one directory only")]
    OneDirectoryOnly,
    /// No directory.
    #[error("verify needs a directory")]
    NoDirectory,
    /// `--time-requirement` without `--time-anchors`: the entries' journal
    /// has its own anchor store (ADR-0095).
    #[error("--time-requirement needs --time-anchors, the entries' own anchor store")]
    TimeAnchorsRequired,
    /// A `--time-requirement` that is not `NS:GRAN`.
    #[error("--time-requirement needs NS:GRAN, two numbers of nanoseconds")]
    TimeRequirement,
}

/// A value that is not 64 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HexError {
    /// Not 64 characters long.
    #[error("{0:?} is not 64 hex digits")]
    Length(String),
    /// A character that is not a hex digit.
    #[error("{0:?} is not hex")]
    NotHex(String),
}

/// A malformed line of a trust file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LineError {
    /// A key with no value.
    #[error("{0:?} has no value")]
    NoValue(String),
    /// A key whose value is not 64 hex digits.
    #[error(transparent)]
    Hex(HexError),
    /// A `journal` value that is not a journal id.
    #[error("{0:?} is not a journal id")]
    JournalId(String),
    /// An unknown key.
    #[error("unknown key {0:?}")]
    UnknownKey(String),
}

/// A trust file `verify` refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// A malformed line, numbered from 1.
    #[error("line {line}: {error}")]
    Line {
        /// The line number, from 1.
        line: usize,
        /// What is wrong with it.
        error: LineError,
    },
    /// No `archive` line.
    #[error("the trust file names no archive")]
    NoArchive,
    /// No `authority` line.
    #[error("the trust file names no authority")]
    NoAuthority,
    /// The time evidence journal's identity is the journal's
    /// (karyos#1128).
    #[error("the time evidence journal needs a journal id of its own")]
    TimeJournal,
    /// No `time-journal` line, where time evidence is verified: its
    /// journal's identity is never guessed (karyos#1128).
    #[error("the trust file has no time-journal line: time evidence needs its journal's id")]
    NoTimeJournal,
}

/// A recording's store that cannot be opened or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The segment store refused.
    #[error(transparent)]
    Segment(SegmentError),
    /// The directory could not be listed.
    #[error(transparent)]
    Io(io::Error),
    /// Segment files are there, but their geometry cannot be recovered.
    #[error("segment files whose geometry cannot be recovered")]
    UnrecoverableGeometry,
}

/// The errors of `karyos-catalog verify`, each with its context; they
/// are formatted only by [`run_verify`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The command line.
    #[error("{0} (karyos-catalog verify --help for the usage)")]
    Usage(#[from] UsageError),
    /// The trust file could not be read.
    #[error("{}: {source}", path.display())]
    TrustRead {
        /// The trust file.
        path: PathBuf,
        /// The read error.
        source: io::Error,
    },
    /// The trust file is malformed.
    #[error("{}: {source}", path.display())]
    Trust {
        /// The trust file.
        path: PathBuf,
        /// What is wrong with it.
        source: TrustError,
    },
    /// An I/O error on a file or directory of the archive or an anchor
    /// store.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// The catalog could not be listed.
    #[error("{}: {source}", dir.display())]
    Catalog {
        /// The archive directory.
        dir: PathBuf,
        /// The catalog error.
        source: CatalogError,
    },
    /// A recording's store could not be opened.
    #[error("{} recording {recording}: {source}", dir.display())]
    Store {
        /// The archive directory.
        dir: PathBuf,
        /// The recording.
        recording: u64,
        /// The store error.
        source: StoreError,
    },
    /// A range of a recording could not be read.
    #[error("{} recording {recording} [{start}, {end}): {source}", dir.display())]
    Read {
        /// The archive directory.
        dir: PathBuf,
        /// The recording.
        recording: u64,
        /// The range's start.
        start: u64,
        /// The range's end.
        end: u64,
        /// The read error.
        source: SegmentError,
    },
    /// The report could not be written.
    #[error("writing the report: {0}")]
    ReportWrite(io::Error),
    /// The copy catalog does not hold a change the chain commits.
    #[error("{}: copy catalog: {source}", dir.display())]
    Copies {
        /// The archive directory.
        dir: PathBuf,
        /// The error.
        source: karyos_archive::integrity::journal::IntegrityError,
    },
    /// The time evidence entries could not be read.
    #[error("{}: {source}", dir.display())]
    TimeEvidence {
        /// The entries' directory.
        dir: PathBuf,
        /// The error.
        source: time_evidence::StoreError,
    },
    /// A signed entry is invalid evidence (karyos#1137): the zero clock
    /// identity other than as the sentinel, or positions its directory's
    /// chain does not seal, or overlapping another entry of its subject.
    /// An integrity failure, never a verdict.
    #[error("{}: invalid time evidence entry of {recording} [{start}, {end}): {why}", dir.display())]
    InvalidTimeEvidence {
        /// The entries' directory.
        dir: PathBuf,
        /// The entry's recording or group.
        recording: u64,
        /// Its start.
        start: u64,
        /// Its end.
        end: u64,
        /// Why.
        why: &'static str,
    },
}

/// Parses the arguments after `verify`: `Ok(None)` for `--help`.
///
/// # Errors
///
/// The usage error.
pub fn parse_verify(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Option<VerifyArgs>, UsageError> {
    let (mut dir, mut trust, mut anchors, mut json) = (None, None, Vec::new(), false);
    let mut time_requirement = None;
    let mut time_anchors = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some("--json") => json = true,
            Some("--time-anchors") => {
                let value = args.next().ok_or(UsageError::AnchorsNeedsValue)?;
                let value = value.to_str().ok_or(UsageError::AnchorsNotText)?;
                let (location, store) = value
                    .split_once('=')
                    .ok_or(UsageError::AnchorsNoSeparator)?;
                time_anchors.push((
                    hex32(location).map_err(UsageError::AnchorsLocation)?,
                    PathBuf::from(store),
                ));
            }
            Some("--time-requirement") => {
                let value = args.next().ok_or(UsageError::TimeRequirement)?;
                let (divergence, granularity) = value
                    .to_str()
                    .and_then(|value| value.split_once(':'))
                    .ok_or(UsageError::TimeRequirement)?;
                time_requirement = Some(Requirement {
                    max_divergence_ns: divergence
                        .parse()
                        .map_err(|_| UsageError::TimeRequirement)?,
                    max_granularity_ns: granularity
                        .parse()
                        .map_err(|_| UsageError::TimeRequirement)?,
                });
            }
            Some("--trust") => {
                let value = args.next().ok_or(UsageError::TrustNeedsFile)?;
                if trust.replace(PathBuf::from(value)).is_some() {
                    return Err(UsageError::TrustTwice);
                }
            }
            Some("--anchors") => {
                let value = args.next().ok_or(UsageError::AnchorsNeedsValue)?;
                let value = value.to_str().ok_or(UsageError::AnchorsNotText)?;
                let (location, store) = value
                    .split_once('=')
                    .ok_or(UsageError::AnchorsNoSeparator)?;
                anchors.push((
                    hex32(location).map_err(UsageError::AnchorsLocation)?,
                    PathBuf::from(store),
                ));
            }
            Some(flag) if flag.starts_with('-') => {
                return Err(UsageError::UnknownOption(flag.to_owned()));
            }
            _ => {
                if dir.replace(PathBuf::from(arg)).is_some() {
                    return Err(UsageError::OneDirectoryOnly);
                }
            }
        }
    }
    let dir = dir.ok_or(UsageError::NoDirectory)?;
    if time_requirement.is_some() && time_anchors.is_empty() {
        return Err(UsageError::TimeAnchorsRequired);
    }
    Ok(Some(VerifyArgs {
        dir,
        trust,
        anchors,
        json,
        time_requirement,
        time_anchors,
    }))
}

/// The time verdict of a directory's entries (karyos#1065).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeReport {
    /// Each entry, with its verdict: `met` only for an entry its own
    /// integrity journal verifies, `no_evidence` otherwise.
    pub entries: Vec<(time_evidence::Entry, Verdict)>,
    /// The sealed positions of each subject with entries that no entry
    /// covers, `(subject, start, end)`: `no_evidence` (ADR-0098 item 2).
    pub gaps: Vec<(u64, u64, u64)>,
    /// The combined verdict: `not_met` over `no_evidence` over `met`.
    pub verdict: Verdict,
}

/// The time verdict of `args.dir`'s entries against its requirement,
/// `None` without one. The entries' own integrity is verified under the
/// same trust, as the trust file's `time-journal`, with `time_anchors`;
/// an entry not verified is `no_evidence`.
///
/// # Errors
///
/// As [`run_checks`], for the entries' directory, and a malformed entry.
pub fn time_report(args: &VerifyArgs) -> Result<Option<TimeReport>, VerifyError> {
    let Some(requirement) = args.time_requirement else {
        return Ok(None);
    };
    let dir = time_evidence::entries_dir(&args.dir);
    let entries = time_evidence::read_sealed(StdDisk, &args.dir).map_err(|source| {
        VerifyError::TimeEvidence {
            dir: dir.clone(),
            source,
        }
    })?;
    let verified: Vec<(u64, u64)> = if entries.is_empty() {
        Vec::new()
    } else {
        let anchors = args.time_anchors.clone();
        let checked = checked(
            &VerifyArgs {
                dir: dir.clone(),
                anchors,
                time_requirement: None,
                time_anchors: Vec::new(),
                ..args.clone()
            },
            Chain::TimeEvidence,
        )?
        .verification;
        checked
            .ranges
            .iter()
            .filter(|range| {
                range.recording == time_evidence::ENTRIES && range.outcome == Outcome::Verified
            })
            .map(|range| (range.start, range.end))
            .collect()
    };
    let gaps = coverage(&args.dir, &dir, &entries)?;
    let length = time_evidence::ENTRY_LENGTH as u64;
    let mut at = 0u64;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let end = at.saturating_add(length);
        let covered = verified
            .iter()
            .any(|&(start, stop)| start <= at && end <= stop);
        // The zero identity is "provenance unknown", never a clock to look
        // up (quantstratum-docs: karyos/design/trace-clocks.md).
        let verdict = if covered && entry.clock != [0; 5] {
            entry.verdict(&requirement)
        } else {
            Verdict::NoEvidence
        };
        out.push((entry, verdict));
        at = end;
    }
    let mut verdicts: Vec<Verdict> = out.iter().map(|(_, verdict)| *verdict).collect();
    verdicts.extend(gaps.iter().map(|_| Verdict::NoEvidence));
    let verdict = time::reduce(&verdicts, Some(&requirement))
        .map(|combined| combined.verdict)
        .unwrap_or(Verdict::NoEvidence);
    Ok(Some(TimeReport {
        entries: out,
        gaps,
        verdict,
    }))
}

/// Checks `entries` against what `archive`'s own integrity journal seals
/// for their subjects (ADR-0098 item 2; docs#975), and returns the sealed
/// positions of each subject with entries that none covers.
///
/// # Errors
///
/// [`VerifyError::InvalidTimeEvidence`] for an entry of the zero identity
/// other than the sentinel, one naming positions the chain does not seal,
/// or one overlapping another of its subject; and the journal's read
/// error.
fn coverage(
    archive: &std::path::Path,
    dir: &std::path::Path,
    entries: &[time_evidence::Entry],
) -> Result<Vec<(u64, u64, u64)>, VerifyError> {
    use std::collections::BTreeMap;
    let invalid = |entry: &time_evidence::Entry, why| VerifyError::InvalidTimeEvidence {
        dir: dir.to_path_buf(),
        recording: entry.recording,
        start: entry.start,
        end: entry.end,
        why,
    };
    let (records, _) = karyos_archive::integrity::journal::read_records(&mut StdDisk, archive)
        .map_err(|source| VerifyError::TimeEvidence {
            dir: dir.to_path_buf(),
            source: time_evidence::StoreError::Io(source),
        })?;
    // Each subject's sealed ranges, merged.
    let mut sealed: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
    for record in records.iter().filter(|record| record.kind.is_range()) {
        sealed
            .entry(record.subject)
            .or_default()
            .push((record.start, record.end));
    }
    for ranges in sealed.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for &(start, end) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        *ranges = merged;
    }
    let mut covered: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
    for entry in entries {
        if !time_evidence::keeps_sentinel(entry) {
            return Err(invalid(
                entry,
                "the zero clock identity with a bound or a record",
            ));
        }
        let inside = sealed.get(&entry.recording).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|&(start, end)| start <= entry.start && entry.end <= end)
        });
        if !inside {
            return Err(invalid(entry, "positions the chain does not seal"));
        }
        covered
            .entry(entry.recording)
            .or_default()
            .push((entry.start, entry.end));
    }
    let mut gaps = Vec::new();
    for (subject, mut spans) in covered {
        spans.sort_unstable();
        if let Some([_, (start, end)]) = spans
            .windows(2)
            .find(|pair| matches!(pair, [a, b] if b.0 < a.1))
        {
            return Err(VerifyError::InvalidTimeEvidence {
                dir: dir.to_path_buf(),
                recording: subject,
                start: *start,
                end: *end,
                why: "overlapping another entry",
            });
        }
        for &(start, end) in sealed.get(&subject).into_iter().flatten() {
            let mut at = start;
            for &(from, to) in spans.iter().filter(|&&(from, to)| to > start && from < end) {
                if from > at {
                    gaps.push((subject, at, from));
                }
                at = at.max(to);
            }
            if at < end {
                gaps.push((subject, at, end));
            }
        }
    }
    Ok(gaps)
}

const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Met => "met",
        Verdict::NoEvidence => "no_evidence",
        Verdict::NotMet => "not_met",
    }
}

/// The time report as text lines.
#[must_use]
pub fn time_text(report: &TimeReport) -> String {
    let mut out = String::new();
    for (entry, verdict) in &report.entries {
        let [_, _, _, domain, epoch] = entry.clock;
        let _ = writeln!(
            out,
            "time recording {} [{}, {}) clock {domain}:{epoch} {}",
            entry.recording,
            entry.start,
            entry.end,
            verdict_name(*verdict)
        );
    }
    for (subject, start, end) in &report.gaps {
        let _ = writeln!(
            out,
            "time recording {subject} [{start}, {end}) uncovered no_evidence"
        );
    }
    let _ = writeln!(out, "time verdict: {}", verdict_name(report.verdict));
    out
}

/// The time report as a JSON value.
#[must_use]
pub fn time_json(report: &TimeReport) -> String {
    let entries: Vec<String> = report
        .entries
        .iter()
        .map(|(entry, verdict)| {
            let [_, _, _, domain, epoch] = entry.clock;
            format!(
                "{{\"recording\":{},\"start\":{},\"end\":{},\"domain\":{},\"epoch\":{},\"verdict\":\"{}\"}}",
                entry.recording,
                entry.start,
                entry.end,
                domain,
                epoch,
                verdict_name(*verdict)
            )
        })
        .collect();
    let gaps: Vec<String> = report
        .gaps
        .iter()
        .map(|(subject, start, end)| {
            format!("{{\"recording\":{subject},\"start\":{start},\"end\":{end}}}")
        })
        .collect();
    format!(
        "{{\"verdict\":\"{}\",\"entries\":[{}],\"gaps\":[{}]}}",
        verdict_name(report.verdict),
        entries.join(","),
        gaps.join(",")
    )
}

pub(crate) fn hex32(text: &str) -> Result<[u8; 32], HexError> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(HexError::Length(text.to_owned()));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).map_err(|_| HexError::NotHex(text.to_owned()))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| HexError::NotHex(text.to_owned()))?;
    }
    Ok(out)
}

/// The trust and externality a trust file states, and the journal id.
///
/// # Errors
///
/// As [`parse_trust_journals`].
pub fn parse_trust(text: &str) -> Result<(TrustRoot, Externality, u64), TrustError> {
    parse_trust_journals(text).map(|(trust, externality, journal, _)| (trust, externality, journal))
}

/// [`parse_trust`], with the time evidence journal's identity last
/// (karyos#1128): `time-journal N`, `None` without that line.
///
/// # Errors
///
/// The first malformed line, a missing archive or authority, and
/// [`TrustError::TimeJournal`] for a time evidence journal with the
/// journal's identity.
pub fn parse_trust_journals(
    text: &str,
) -> Result<(TrustRoot, Externality, u64, Option<u64>), TrustError> {
    let mut archive = None;
    let mut authorities: Vec<[u8; PUBLIC_KEY_LENGTH]> = Vec::new();
    let mut journal = 0u64;
    let mut time_journal = None;
    let mut externality = Externality::default();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |error: LineError| TrustError::Line {
            line: number.saturating_add(1),
            error,
        };
        let hex = |value: &str| hex32(value).map_err(|error| at(LineError::Hex(error)));
        let (key, value) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| at(LineError::NoValue(line.to_owned())))?;
        let value = value.trim();
        match key {
            "archive" => archive = Some(hex(value)?),
            "authority" => authorities.push(hex(value)?),
            "journal" => {
                journal = value
                    .parse()
                    .map_err(|_| at(LineError::JournalId(value.to_owned())))?;
            }
            "time-journal" => {
                time_journal = Some(
                    value
                        .parse()
                        .map_err(|_| at(LineError::JournalId(value.to_owned())))?,
                );
            }
            "local" => {
                externality.local_locations.insert(hex(value)?);
            }
            "anchors" => {
                externality.anchored_by_this.insert(hex(value)?);
            }
            other => return Err(at(LineError::UnknownKey(other.to_owned()))),
        }
    }
    let archive_id = archive.ok_or(TrustError::NoArchive)?;
    if authorities.is_empty() {
        return Err(TrustError::NoAuthority);
    }
    if time_journal == Some(journal) {
        return Err(TrustError::TimeJournal);
    }
    externality.local_archive = archive_id;
    Ok((
        TrustRoot {
            archive_id,
            authorities,
        },
        externality,
        journal,
        time_journal,
    ))
}

/// Opens each recording's store read only, once.
///
/// A recording with no segment files has no store (`None`); a store that
/// cannot be opened, or a read that fails, is an error of the command,
/// never reported as an index shortened below a seal.
struct Stores {
    dir: PathBuf,
    open: BTreeMap<u64, Option<SegmentStore<ReadOnly<StdDisk>>>>,
    /// The first read error, which fails the command.
    error: Option<VerifyError>,
}

impl Stores {
    fn store(
        &mut self,
        recording: u64,
    ) -> Result<Option<&mut SegmentStore<ReadOnly<StdDisk>>>, VerifyError> {
        if !self.open.contains_key(&recording) {
            let at = |source: StoreError| VerifyError::Store {
                dir: self.dir.clone(),
                recording,
                source,
            };
            let mut disk = ReadOnly(StdDisk);
            let store = match recorded_geometry(&mut disk, &self.dir, recording)
                .map_err(|error| at(StoreError::Segment(error)))?
            {
                // No geometry: an absent store only if the recording has no
                // segment file at all; files whose geometry cannot be
                // recovered are a damaged store.
                None => {
                    let prefix = format!("{recording:016x}-");
                    let names = disk
                        .list(&self.dir)
                        .map_err(|error| at(StoreError::Io(error)))?;
                    if names.iter().any(|name| name.starts_with(&prefix)) {
                        return Err(at(StoreError::UnrecoverableGeometry));
                    }
                    None
                }
                Some(geometry) => Some(
                    SegmentStore::open_verified(
                        disk,
                        &self.dir,
                        recording,
                        geometry,
                        SyncPolicy::None,
                    )
                    .map_err(|error| at(StoreError::Segment(error)))?,
                ),
            };
            let _ = self.open.insert(recording, store);
        }
        Ok(self.open.get_mut(&recording).and_then(Option::as_mut))
    }

    fn read(&mut self, recording: u64, start: u64, end: u64) -> RangeBytes {
        let store = match self.store(recording) {
            Ok(Some(store)) => store,
            Ok(None) => return RangeBytes::Missing,
            Err(error) => {
                let _ = self.error.get_or_insert(error);
                return RangeBytes::Missing;
            }
        };
        // A seal is corrupt input: its range is checked against what the
        // store holds before anything is allocated for it.
        if start > end || end > store.written() {
            return RangeBytes::Missing;
        }
        let Some(length) = end
            .checked_sub(start)
            .and_then(|length| usize::try_from(length).ok())
        else {
            return RangeBytes::Missing;
        };
        let mut buf = Vec::new();
        if buf.try_reserve_exact(length).is_err() {
            return RangeBytes::Missing;
        }
        buf.resize(length, 0);
        match store.read(start, &mut buf) {
            Ok(()) => RangeBytes::Bytes(buf),
            Err(error) => {
                let _ = self.error.get_or_insert(VerifyError::Read {
                    dir: self.dir.clone(),
                    recording,
                    start,
                    end,
                    source: error,
                });
                RangeBytes::Missing
            }
        }
    }
}

/// Verifies the archive directory `args.dir`.
///
/// # Errors
///
/// An I/O error, a malformed trust file, or a store that cannot be
/// opened or read.
pub fn run_checks(args: &VerifyArgs) -> Result<Verification, VerifyError> {
    checked(args, Chain::Integrity).map(|checked| checked.verification)
}

/// A verification and the journal snapshot it checked, from which the
/// copies are replayed: a second read of a live archive could hold
/// records this verification never checked (karyos#1087 review).
struct Checked {
    verification: Verification,
    records: Vec<SealRecord>,
    /// The locations the trust file names as this directory's: its
    /// Archive and its `local` stores; empty without a trust file.
    local: BTreeSet<[u8; 32]>,
}

impl Checked {
    /// The records of the accepted prefix: those before the journal's
    /// first inconsistent record.
    fn accepted(&self) -> &[SealRecord] {
        let end = self
            .verification
            .journal_break
            .and_then(|position| usize::try_from(position).ok())
            .map_or(self.records.len(), |position| {
                position.min(self.records.len())
            });
        self.records.get(..end).unwrap_or_default()
    }
}

/// Which journal of the trust file a directory's chain is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    /// The integrity journal, `journal`.
    Integrity,
    /// The time evidence entries' journal, `time-journal` (karyos#1128).
    TimeEvidence,
}

/// [`run_checks`] of `args.dir` as the journal `chain`, keeping the
/// journal snapshot it verified: its heads and anchors must name that
/// journal's identity, so another chain's anchor is refused as
/// `WrongJournal`.
fn checked(args: &VerifyArgs, chain: Chain) -> Result<Checked, VerifyError> {
    let dir = &args.dir;
    let at = |source: io::Error| VerifyError::Io {
        path: dir.clone(),
        source,
    };
    let mut disk = ReadOnly(StdDisk);
    let (records, journal_fault) = read_records(&mut disk, dir).map_err(at)?;
    let keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]> =
        read_entries(&mut disk, dir, KEYS_FILE).map_err(at)?;
    let heads: Vec<[u8; SIGNED_HEAD_LENGTH]> =
        read_entries(&mut disk, dir, HEADS_FILE).map_err(at)?;
    let (trust, externality, journal_id) = match &args.trust {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|source| VerifyError::TrustRead {
                path: path.clone(),
                source,
            })?;
            let (trust, externality, journal, time_journal) =
                parse_trust_journals(&text).map_err(|source| VerifyError::Trust {
                    path: path.clone(),
                    source,
                })?;
            let journal = match chain {
                Chain::Integrity => journal,
                Chain::TimeEvidence => time_journal.ok_or_else(|| VerifyError::Trust {
                    path: path.clone(),
                    source: TrustError::NoTimeJournal,
                })?,
            };
            (Some(trust), externality, journal)
        }
        None => (None, Externality::default(), 0),
    };
    // Each store named on the command line is read from the store itself,
    // which is what confirms an anchor's counter and receipt.
    let mut anchors = Vec::new();
    let mut anchor_stores = Vec::new();
    let mut anchor_faults = 0u64;
    for (location, store) in &args.anchors {
        // A store named on the command line must be there: a mistyped path
        // is an error, never an empty store.
        let ledger = store.join(ANCHOR_FILE);
        if let Err(source) = disk.open_read(&ledger) {
            return Err(VerifyError::Io {
                path: ledger,
                source,
            });
        }
        let entries: Vec<[u8; ANCHOR_LENGTH]> = read_entries(&mut disk, store, ANCHOR_FILE)
            .map_err(|source| VerifyError::Io {
                path: store.clone(),
                source,
            })?;
        let stored = StoredAnchors::new(*location, entries);
        anchors.extend(stored.anchors());
        anchor_faults = anchor_faults.saturating_add(stored.malformed());
        anchor_stores.push(stored);
    }

    // Every recording the catalog or the chain names, with its written end.
    let mut recordings: BTreeSet<u64> = records
        .iter()
        .filter(|record| record.kind.is_range())
        .map(|record| record.subject)
        .collect();
    // A directory that cannot be listed is an error, never an empty
    // report; one without a catalog lists as missing.
    let listing = list(ReadOnly(StdDisk), dir).map_err(|source| VerifyError::Catalog {
        dir: dir.clone(),
        source,
    })?;
    recordings.extend(listing.recordings.iter().map(|recording| recording.id));
    let mut stores = Stores {
        dir: dir.clone(),
        open: BTreeMap::new(),
        error: None,
    };
    let mut written: Vec<(u64, u64)> = Vec::new();
    for &recording in &recordings {
        if let Some(store) = stores.store(recording)? {
            written.push((recording, store.written()));
        }
    }
    let evidence = Evidence {
        records: &records,
        journal_fault,
        journal_id,
        trust: trust.as_ref(),
        registry: &keys,
        heads: &heads,
        anchors: &anchors,
        anchor_faults,
        stores: &anchor_stores,
        externality: &externality,
        written: &written,
    };
    let verification = verify(&evidence, |recording, start, end| {
        stores.read(recording, start, end)
    });
    match stores.error {
        Some(error) => Err(error),
        None => {
            let local = if trust.is_some() {
                let mut local = externality.local_locations.clone();
                let _ = local.insert(externality.local_archive);
                local
            } else {
                BTreeSet::new()
            };
            Ok(Checked {
                verification,
                records,
                local,
            })
        }
    }
}

/// The custody label of the signed coverage, as reported: a test
/// signer's heads are "no custody separation".
fn custody_name(custody: Option<Custody>) -> &'static str {
    match custody {
        None => "none",
        Some(Custody::NoSeparation) => "no custody separation",
        Some(Custody::Declared) => "declared",
        Some(Custody::ExternallyEvidenced) => "externally evidenced",
        Some(_) => "unknown",
    }
}

/// The report as text: one line per range, then the coverage.
#[must_use]
pub fn text(verification: &Verification) -> String {
    let mut out = String::new();
    for range in &verification.ranges {
        let _ = write!(
            out,
            "recording {} [{}, {}) {}",
            range.recording,
            range.start,
            range.end,
            range.outcome.name()
        );
        if let Some(counter) = range.counter {
            let _ = write!(out, " seal={counter}");
        }
        if !range.reasons.is_empty() {
            let reasons: Vec<&str> = range.reasons.iter().map(|reason| reason.name()).collect();
            let _ = write!(out, " reasons={}", reasons.join(","));
        }
        if let Some(first) = range.first_inconsistent {
            let _ = write!(out, " first_inconsistent={first}");
        }
        if range.outcome.is_unverifiable() {
            out.push_str(" unverifiable");
        }
        if let Some(statement) = range.outcome.statement() {
            let _ = write!(out, ": {statement}");
        }
        out.push('\n');
    }
    if let Some(first) = verification.journal_break {
        let _ = writeln!(
            out,
            "journal inconsistent first_inconsistent={first}: nothing from this record on is verified"
        );
    }
    if !verification.evidence.is_empty() {
        let reasons: Vec<&str> = verification
            .evidence
            .iter()
            .map(|reason| reason.name())
            .collect();
        let _ = writeln!(out, "evidence inconsistent reasons={}", reasons.join(","));
    }
    let coverage = &verification.coverage;
    let through = |value: Option<u64>| value.map_or_else(|| "none".to_owned(), |v| v.to_string());
    let _ = writeln!(
        out,
        "coverage: {} records, signed through {} ({}), anchored through {}",
        coverage.records,
        through(coverage.signed_through),
        custody_name(coverage.custody),
        through(coverage.anchored_through)
    );
    out.push_str("time evidence: not evaluated by the integrity verifier\n");
    out
}

/// The report as one JSON object, with integrity and time in separate
/// fields.
#[must_use]
pub fn json(verification: &Verification) -> String {
    let mut out = String::from("{\"integrity\":[");
    for (index, range) in verification.ranges.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let reasons: Vec<String> = range
            .reasons
            .iter()
            .map(|reason| format!("\"{}\"", reason.name()))
            .collect();
        let option =
            |value: Option<u64>| value.map_or_else(|| "null".to_owned(), |v| v.to_string());
        let statement = range
            .outcome
            .statement()
            .map_or_else(|| "null".to_owned(), |text| format!("\"{text}\""));
        let _ = write!(
            out,
            "{{\"recording\":{},\"start\":{},\"end\":{},\"seal\":{},\"outcome\":\"{}\",\"reasons\":[{}],\"first_inconsistent\":{},\"unverifiable\":{},\"statement\":{}}}",
            range.recording,
            range.start,
            range.end,
            option(range.counter),
            range.outcome.name(),
            reasons.join(","),
            option(range.first_inconsistent),
            range.outcome.is_unverifiable(),
            statement
        );
    }
    let evidence: Vec<String> = verification
        .evidence
        .iter()
        .map(|reason| format!("\"{}\"", reason.name()))
        .collect();
    let coverage = &verification.coverage;
    let option = |value: Option<u64>| value.map_or_else(|| "null".to_owned(), |v| v.to_string());
    let _ = writeln!(
        out,
        "],\"journal_first_inconsistent\":{},\"evidence\":[{}],\"coverage\":{{\"records\":{},\"signed_through\":{},\"custody\":\"{}\",\"anchored_through\":{}}},\"time\":\"not_evaluated\"}}",
        option(verification.journal_break),
        evidence.join(","),
        coverage.records,
        option(coverage.signed_through),
        custody_name(coverage.custody),
        option(coverage.anchored_through)
    );
    out
}

/// The copies `verify` reports: the current copies the chain commits,
/// and the first copy change the catalog does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyReport {
    /// The current copies, each with its recorded enforcement and what
    /// its files carry; empty when a change could not be replayed.
    pub copies: Vec<(CopyRecord, Observed)>,
    /// The counter of the first copy change the chain commits that the
    /// copy catalog does not hold or holds in a form that does not match:
    /// an inconsistency of the evidence, never an error of the command.
    pub first_inconsistent: Option<u64>,
}

/// What `verify` reads of a copy's immutable attribute on its segment
/// files, beside the enforcement the catalog records (karyos#1087).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Observed {
    /// Not read: the copy is removed, or its location is not one the
    /// trust file names as this directory's (`archive` or `local`).
    NotChecked,
    /// Every segment file of the copy carries the immutable attribute.
    Immutable,
    /// A segment file of the copy does not carry it.
    Absent,
    /// It could not be read: no segment file, a platform or file system
    /// without the attribute, or a read that failed.
    Unknown,
}

impl Observed {
    /// The name `verify` reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Immutable => "immutable_attribute",
            Self::Absent => "none",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether `copy` records an immutable attribute its files do not carry:
/// an inconsistency, a protection the catalog states that is not there.
fn mismatched(copy: &CopyRecord, observed: Observed) -> bool {
    copy.enforcement == Enforcement::ImmutableAttribute && observed == Observed::Absent
}

/// Whether the file at `path` carries the immutable attribute: `None`
/// when that cannot be read.
#[cfg(target_os = "linux")]
fn immutable_attribute(path: &std::path::Path) -> Option<bool> {
    karyos_sys::fs::is_immutable(path).ok().flatten()
}

/// Whether the file at `path` carries the immutable attribute, the user
/// or the system flag of `chflags`: `None` when that cannot be read.
#[cfg(target_os = "macos")]
fn immutable_attribute(path: &std::path::Path) -> Option<bool> {
    use std::os::macos::fs::MetadataExt as _;
    const UF_IMMUTABLE: u32 = 0x0000_0002;
    const SF_IMMUTABLE: u32 = 0x0002_0000;
    std::fs::symlink_metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|metadata| metadata.st_flags() & (UF_IMMUTABLE | SF_IMMUTABLE) != 0)
}

/// No immutable attribute is read on this platform.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn immutable_attribute(_path: &std::path::Path) -> Option<bool> {
    None
}

/// What the segment files of `copy` carry, read from `stores`.
fn observe(stores: &mut Stores, copy: &CopyRecord, local: &BTreeSet<[u8; 32]>) -> Observed {
    if copy.state == CopyState::Removed || !local.contains(&copy.location) {
        return Observed::NotChecked;
    }
    let files = match stores.store(copy.recording) {
        Ok(Some(store)) => store.segment_files().unwrap_or_default(),
        Ok(None) | Err(_) => Vec::new(),
    };
    if files.is_empty() {
        return Observed::Unknown;
    }
    let mut observed = Observed::Immutable;
    for file in &files {
        match immutable_attribute(file) {
            Some(true) => {}
            Some(false) => return Observed::Absent,
            None => observed = Observed::Unknown,
        }
    }
    observed
}

/// The current copies of `args.dir`'s copy catalog, as the journal
/// `records` commits them, each with its enforcement (karyos#1087).
/// `records` is the accepted prefix of the journal snapshot the
/// verification checked: never a second read, and nothing from the
/// journal's first inconsistent record on. A copy change the catalog
/// does not hold, a truncated catalog for one, is reported in
/// [`CopyReport::first_inconsistent`]. The immutable attribute of each
/// copy at a location in `local` is read from its segment files in
/// `args.dir`, never assumed from the record.
///
/// # Errors
///
/// An I/O error on the catalog.
pub fn copies_report(
    args: &VerifyArgs,
    records: &[SealRecord],
    local: &BTreeSet<[u8; 32]>,
) -> Result<CopyReport, VerifyError> {
    let dir = &args.dir;
    let at = |source: io::Error| VerifyError::Io {
        path: dir.clone(),
        source,
    };
    let mut disk = ReadOnly(StdDisk);
    let entries: Vec<[u8; COPY_RECORD_LENGTH]> =
        read_entries(&mut disk, dir, COPIES_FILE).map_err(at)?;
    match replay_current(records, &entries) {
        Ok(copies) => {
            let mut stores = Stores {
                dir: dir.clone(),
                open: BTreeMap::new(),
                error: None,
            };
            let copies = copies
                .into_iter()
                .map(|copy| {
                    let observed = observe(&mut stores, &copy, local);
                    (copy, observed)
                })
                .collect();
            Ok(CopyReport {
                copies,
                first_inconsistent: None,
            })
        }
        Err(IntegrityError::Unrecorded { counter }) => Ok(CopyReport {
            copies: Vec::new(),
            first_inconsistent: Some(counter),
        }),
        Err(source) => Err(VerifyError::Copies {
            dir: dir.clone(),
            source,
        }),
    }
}

const fn state_name(state: CopyState) -> &'static str {
    match state {
        CopyState::Unverified => "unverified",
        CopyState::Verified => "verified",
        CopyState::Removed => "removed",
        _ => "unknown",
    }
}

const fn enforcement_name(enforcement: Enforcement) -> &'static str {
    match enforcement {
        Enforcement::Unsupported => "none",
        Enforcement::ImmutableAttribute => "immutable_attribute",
        Enforcement::ObjectLock => "object_lock",
        _ => "unknown",
    }
}

fn location_hex(location: &[u8; 32]) -> String {
    location
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The copies as text lines.
#[must_use]
pub fn copies_text(report: &CopyReport) -> String {
    let mut out = String::new();
    for (copy, observed) in &report.copies {
        let _ = write!(
            out,
            "copy recording {} [{}, {}) location {} {} enforcement {} observed {}",
            copy.recording,
            copy.start,
            copy.end,
            location_hex(&copy.location),
            state_name(copy.state),
            enforcement_name(copy.enforcement),
            observed.name()
        );
        if mismatched(copy, *observed) {
            out.push_str(" enforcement_mismatch");
        }
        out.push('\n');
    }
    if let Some(first) = report.first_inconsistent {
        let _ = writeln!(
            out,
            "copies inconsistent first_inconsistent={first}: the copy catalog does not hold this change"
        );
    }
    out
}

/// The copies as JSON fields: `copies`, an array, and
/// `copies_first_inconsistent`.
#[must_use]
pub fn copies_json(report: &CopyReport) -> String {
    let items: Vec<String> = report
        .copies
        .iter()
        .map(|(copy, observed)| {
            format!(
                "{{\"recording\":{},\"start\":{},\"end\":{},\"location\":\"{}\",\"state\":\"{}\",\"enforcement\":\"{}\",\"observed\":\"{}\",\"mismatch\":{}}}",
                copy.recording,
                copy.start,
                copy.end,
                location_hex(&copy.location),
                state_name(copy.state),
                enforcement_name(copy.enforcement),
                observed.name(),
                mismatched(copy, *observed)
            )
        })
        .collect();
    format!(
        "\"copies\":[{}],\"copies_first_inconsistent\":{}",
        items.join(","),
        report
            .first_inconsistent
            .map_or_else(|| "null".to_owned(), |first| first.to_string())
    )
}

/// `report` with the copies placed before its time part: a `copies`
/// field before `time` in JSON, lines before the time lines in text.
fn insert_copies(report: String, copies: &CopyReport, json: bool) -> String {
    let (marker, inserted) = if json {
        ("\"time\":", format!("{},", copies_json(copies)))
    } else {
        ("time ", copies_text(copies))
    };
    let at = if json {
        report.rfind(marker)
    } else {
        // The first time line: the verdict lines or "time evidence:".
        report
            .match_indices(marker)
            .find(|(at, _)| *at == 0 || report.get(at.saturating_sub(1)..*at) == Some("\n"))
            .map(|(at, _)| at)
    };
    match at {
        Some(at) => format!(
            "{}{}{}",
            report.get(..at).unwrap_or_default(),
            inserted,
            report.get(at..).unwrap_or_default()
        ),
        None => report,
    }
}

/// Runs `verify` on `args` (the arguments after `verify`), printing the
/// help, the report (to `stdout`) or the error (to `stderr`), and returns
/// the exit status.
pub fn run_verify(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> u8 {
    let parsed = match parse_verify(args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            let _ = stdout.write_all(HELP.as_bytes());
            return 0;
        }
        Err(error) => return report_error(stderr, &VerifyError::Usage(error)),
    };
    match checked(&parsed, Chain::Integrity).and_then(|checked| {
        let time = time_report(&parsed)?;
        let copies = copies_report(&parsed, checked.accepted(), &checked.local)?;
        Ok((checked.verification, time, copies))
    }) {
        Ok((verification, time, copies)) => {
            let report = match (&time, parsed.json) {
                (None, true) => json(&verification),
                (None, false) => text(&verification),
                (Some(time), true) => {
                    let integrity = json(&verification);
                    let field = "\"time\":\"not_evaluated\"";
                    match integrity.rfind(field) {
                        Some(at) => format!(
                            "{}\"time\":{}{}",
                            integrity.get(..at).unwrap_or_default(),
                            time_json(time),
                            integrity
                                .get(at.saturating_add(field.len())..)
                                .unwrap_or_default()
                        ),
                        None => integrity,
                    }
                }
                (Some(time), false) => {
                    let integrity = text(&verification);
                    let head = integrity
                        .strip_suffix("time evidence: not evaluated by the integrity verifier\n")
                        .unwrap_or(&integrity);
                    format!("{head}{}", time_text(time))
                }
            };
            // Each copy's enforcement, before the time (karyos#1087).
            let report = insert_copies(report, &copies, parsed.json);
            // A report that could not be written is an error, never a
            // status automation would read as the evidence's.
            if let Err(error) = stdout
                .write_all(report.as_bytes())
                .and_then(|()| stdout.flush())
            {
                return report_error(stderr, &VerifyError::ReportWrite(error));
            }
            if verification.journal_break.is_some()
                || copies.first_inconsistent.is_some()
                || copies
                    .copies
                    .iter()
                    .any(|(copy, observed)| mismatched(copy, *observed))
                || !verification.evidence.is_empty()
                || verification
                    .ranges
                    .iter()
                    .any(|range| range.outcome == Outcome::Inconsistent)
            {
                EXIT_INCONSISTENT
            } else {
                0
            }
        }
        Err(error) => report_error(stderr, &error),
    }
}

/// Prints `error` to `stderr`, the one place an error becomes text, and
/// returns its exit status.
fn report_error(stderr: &mut dyn io::Write, error: &VerifyError) -> u8 {
    let _ = writeln!(stderr, "karyos-catalog: {error}");
    EXIT_ERROR
}

#[cfg(test)]
pub(crate) mod tests;
