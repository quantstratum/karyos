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
use std::path::PathBuf;

use karyos_archive::catalog::list;
use karyos_archive::disk::{Disk as _, ReadOnly, StdDisk};
use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH, Externality, StoredAnchors};
use karyos_archive::integrity::journal::read_records;
use karyos_archive::integrity::ledger::read_entries;
use karyos_archive::integrity::trust::{
    Custody, HEADS_FILE, KEYS_FILE, PUBLIC_KEY_LENGTH, REGISTRY_ENTRY_LENGTH, SIGNED_HEAD_LENGTH,
    TrustRoot,
};
use karyos_archive::integrity::verify::{Evidence, Outcome, RangeBytes, Verification, verify};
use karyos_archive::segment::{SegmentStore, SyncPolicy, recorded_geometry};

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
}

/// Parses the arguments after `verify`: `Ok(None)` for `--help`.
///
/// # Errors
///
/// The usage error, as text.
pub fn parse_verify(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Option<VerifyArgs>, String> {
    let (mut dir, mut trust, mut anchors, mut json) = (None, None, Vec::new(), false);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some("--json") => json = true,
            Some("--trust") => {
                let value = args.next().ok_or("--trust needs a file")?;
                if trust.replace(PathBuf::from(value)).is_some() {
                    return Err("--trust given twice".into());
                }
            }
            Some("--anchors") => {
                let value = args.next().ok_or("--anchors needs HEX=DIR")?;
                let value = value.to_str().ok_or("--anchors HEX=DIR is not text")?;
                let (location, store) = value
                    .split_once('=')
                    .ok_or("--anchors needs HEX=DIR: the store's location, then its directory")?;
                anchors.push((hex32(location)?, PathBuf::from(store)));
            }
            Some(flag) if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            _ => {
                if dir.replace(PathBuf::from(arg)).is_some() {
                    return Err("one directory only".into());
                }
            }
        }
    }
    let dir = dir.ok_or("verify needs a directory")?;
    Ok(Some(VerifyArgs {
        dir,
        trust,
        anchors,
        json,
    }))
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("{text:?} is not 64 hex digits"));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{text:?} is not hex"))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| format!("{text:?} is not hex"))?;
    }
    Ok(out)
}

/// The trust and externality a trust file states, and the journal id.
///
/// # Errors
///
/// The first malformed line, as text.
pub fn parse_trust(text: &str) -> Result<(TrustRoot, Externality, u64), String> {
    let mut archive = None;
    let mut authorities: Vec<[u8; PUBLIC_KEY_LENGTH]> = Vec::new();
    let mut journal = 0u64;
    let mut externality = Externality::default();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |error: String| format!("line {}: {error}", number.saturating_add(1));
        let (key, value) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| at(format!("{line:?} has no value")))?;
        let value = value.trim();
        match key {
            "archive" => archive = Some(hex32(value).map_err(at)?),
            "authority" => authorities.push(hex32(value).map_err(at)?),
            "journal" => {
                journal = value
                    .parse()
                    .map_err(|_| at(format!("{value:?} is not a journal id")))?;
            }
            "local" => {
                externality
                    .local_locations
                    .insert(hex32(value).map_err(at)?);
            }
            "anchors" => {
                externality
                    .anchored_by_this
                    .insert(hex32(value).map_err(at)?);
            }
            other => return Err(at(format!("unknown key {other:?}"))),
        }
    }
    let archive_id = archive.ok_or("the trust file names no archive")?;
    if authorities.is_empty() {
        return Err("the trust file names no authority".into());
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
    error: Option<String>,
}

impl Stores {
    fn store(
        &mut self,
        recording: u64,
    ) -> Result<Option<&mut SegmentStore<ReadOnly<StdDisk>>>, String> {
        if !self.open.contains_key(&recording) {
            let at = |error: &dyn std::fmt::Display| {
                format!("{} recording {recording}: {error}", self.dir.display())
            };
            let mut disk = ReadOnly(StdDisk);
            let store = match recorded_geometry(&mut disk, &self.dir, recording)
                .map_err(|error| at(&error))?
            {
                // No geometry: an absent store only if the recording has no
                // segment file at all; files whose geometry cannot be
                // recovered are a damaged store.
                None => {
                    let prefix = format!("{recording:016x}-");
                    let names = disk.list(&self.dir).map_err(|error| at(&error))?;
                    if names.iter().any(|name| name.starts_with(&prefix)) {
                        return Err(at(&"segment files whose geometry cannot be recovered"));
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
                    .map_err(|error| at(&error))?,
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
                let _ = self.error.get_or_insert(format!(
                    "{} recording {recording} [{start}, {end}): {error}",
                    self.dir.display()
                ));
                RangeBytes::Missing
            }
        }
    }
}

/// Verifies the archive directory `args.dir`.
///
/// # Errors
///
/// An I/O error or a malformed trust file, as text.
pub fn run_checks(args: &VerifyArgs) -> Result<Verification, String> {
    let dir = &args.dir;
    let at = |error: std::io::Error| format!("{}: {error}", dir.display());
    let mut disk = ReadOnly(StdDisk);
    let (records, journal_fault) = read_records(&mut disk, dir).map_err(at)?;
    let keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]> =
        read_entries(&mut disk, dir, KEYS_FILE).map_err(at)?;
    let heads: Vec<[u8; SIGNED_HEAD_LENGTH]> =
        read_entries(&mut disk, dir, HEADS_FILE).map_err(at)?;
    let (trust, externality, journal_id) = match &args.trust {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let (trust, externality, journal) =
                parse_trust(&text).map_err(|error| format!("{}: {error}", path.display()))?;
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
        if let Err(error) = disk.open_read(&ledger) {
            return Err(format!("{}: {error}", ledger.display()));
        }
        let entries: Vec<[u8; ANCHOR_LENGTH]> = read_entries(&mut disk, store, ANCHOR_FILE)
            .map_err(|error| format!("{}: {error}", store.display()))?;
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
    let listing =
        list(ReadOnly(StdDisk), dir).map_err(|error| format!("{}: {error}", dir.display()))?;
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
        Err(error) => {
            let _ = writeln!(
                stderr,
                "karyos-catalog: {error} (karyos-catalog verify --help for the usage)"
            );
            return EXIT_ERROR;
        }
    };
    match run_checks(&parsed) {
        Ok(verification) => {
            let report = if parsed.json {
                json(&verification)
            } else {
                text(&verification)
            };
            // A report that could not be written is an error, never a
            // status automation would read as the evidence's.
            if let Err(error) = stdout
                .write_all(report.as_bytes())
                .and_then(|()| stdout.flush())
            {
                let _ = writeln!(stderr, "karyos-catalog: writing the report: {error}");
                return EXIT_ERROR;
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
        Err(error) => {
            let _ = writeln!(stderr, "karyos-catalog: {error}");
            EXIT_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
