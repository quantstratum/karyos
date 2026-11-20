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
//! local <64 hex digits>       a store on this host, never external
//! anchors <64 hex digits>     an Archive this one anchors (circular)
//! ```
//!
//! Without `--trust`, every sealed range is `inconsistent` with reason
//! `untrusted_evidence`. Each `--anchors LOCATION=DIR` adds the operator
//! export store in DIR, which the operator identifies by its location
//! digest outside the export: an anchor counts only if it names that
//! location. Exit status: 0 when nothing is inconsistent, 1 when a range
//! or the journal is, 2 for an error, including a report that could not
//! be written.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;

use karyos_archive::catalog::{CatalogError, list};
use karyos_archive::disk::{Disk as _, ReadOnly, StdDisk};
use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH, Externality, StoredAnchors};
use karyos_archive::integrity::journal::read_records;
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
                 `archive HEX`, `authority HEX`, `journal N`, `local HEX`,
                 `anchors HEX`; without it nothing is trusted
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
                 repeatable; without it --anchors serves both
  --json         one JSON object instead of text
  -h, --help     print this text

Exit status: 0 nothing inconsistent; 1 a range or the journal inconsistent;
2 an error, or a report that could not be written.
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
    /// The anchor stores of the entries' own journal; empty uses
    /// `anchors`.
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
    /// The time evidence entries could not be read.
    #[error("{}: {source}", dir.display())]
    TimeEvidence {
        /// The entries' directory.
        dir: PathBuf,
        /// The error.
        source: time_evidence::StoreError,
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
    /// The combined verdict: `not_met` over `no_evidence` over `met`.
    pub verdict: Verdict,
}

/// The time verdict of `args.dir`'s entries against its requirement,
/// `None` without one. The entries' own integrity is verified under the
/// same trust and anchors; an entry not verified is `no_evidence`.
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
        let anchors = if args.time_anchors.is_empty() {
            args.anchors.clone()
        } else {
            args.time_anchors.clone()
        };
        let checked = run_checks(&VerifyArgs {
            dir: dir.clone(),
            anchors,
            time_requirement: None,
            time_anchors: Vec::new(),
            ..args.clone()
        })?;
        checked
            .ranges
            .iter()
            .filter(|range| {
                range.recording == time_evidence::ENTRIES && range.outcome == Outcome::Verified
            })
            .map(|range| (range.start, range.end))
            .collect()
    };
    let length = time_evidence::ENTRY_LENGTH as u64;
    let mut at = 0u64;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let end = at.saturating_add(length);
        let covered = verified
            .iter()
            .any(|&(start, stop)| start <= at && end <= stop);
        let verdict = if covered {
            entry.verdict(&requirement)
        } else {
            Verdict::NoEvidence
        };
        out.push((entry, verdict));
        at = end;
    }
    let verdicts: Vec<Verdict> = out.iter().map(|(_, verdict)| *verdict).collect();
    let verdict = time::reduce(&verdicts, Some(&requirement))
        .map(|combined| combined.verdict)
        .unwrap_or(Verdict::NoEvidence);
    Ok(Some(TimeReport {
        entries: out,
        verdict,
    }))
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
    format!(
        "{{\"verdict\":\"{}\",\"entries\":[{}]}}",
        verdict_name(report.verdict),
        entries.join(",")
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
/// The first malformed line, or a missing archive or authority.
pub fn parse_trust(text: &str) -> Result<(TrustRoot, Externality, u64), TrustError> {
    let mut archive = None;
    let mut authorities: Vec<[u8; PUBLIC_KEY_LENGTH]> = Vec::new();
    let mut journal = 0u64;
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
    externality.local_archive = archive_id;
    Ok((
        TrustRoot {
            archive_id,
            authorities,
        },
        externality,
        journal,
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
            let (trust, externality, journal) =
                parse_trust(&text).map_err(|source| VerifyError::Trust {
                    path: path.clone(),
                    source,
                })?;
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
        None => Ok(verification),
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
    match run_checks(&parsed)
        .and_then(|verification| time_report(&parsed).map(|time| (verification, time)))
    {
        Ok((verification, time)) => {
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
            // A report that could not be written is an error, never a
            // status automation would read as the evidence's.
            if let Err(error) = stdout
                .write_all(report.as_bytes())
                .and_then(|()| stdout.flush())
            {
                return report_error(stderr, &VerifyError::ReportWrite(error));
            }
            if verification.journal_break.is_some()
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
mod tests;
