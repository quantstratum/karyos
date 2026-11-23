// SPDX-License-Identifier: Apache-2.0
//! `karyos-catalog export` and `karyos-catalog verify-export` (ADR-0103;
//! quantstratum-docs: karyos/design/archive-export.md; karyos#668).
//!
//! ```text
//! karyos-catalog export <archive> --trust <file> --recording <id>... \
//!     [--anchors <hex>=<dir>]... [--time] [--clock-records <file>] \
//!     [--schema <id>:<version>=<file>]... \
//!     [--created-ns <ns>] --out <file>
//! karyos-catalog verify-export <file> --trust <file> \
//!     [--anchors <hex>=<dir>]... [--time-requirement <max>:<gran>] [--json]
//! ```
//!
//! The export gathers, from an Archive's own files, each carried journal
//! from its genesis to the later of the last record sealing exported bytes
//! and its latest anchored head; the registry, heads and anchors over it;
//! the exported recordings' bytes; the policy versions and bindings it
//! seals; and, with `--time`, the time evidence entries' journal and store.
//! `verify-export` checks an export offline with the external trust only.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use karyos_archive::catalog::list;
use karyos_archive::disk::{Disk as _, ReadOnly, StdDisk};
use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH, Anchor, StoredAnchors};
use karyos_archive::integrity::export::assemble::{
    ExportContents, JournalExport, RecordingExport, assemble,
};
use karyos_archive::integrity::export::offline::{OfflineTrust, Role, verify_export};
use karyos_archive::integrity::journal::read_records;
use karyos_archive::integrity::ledger::read_entries;
use karyos_archive::integrity::retention::{POLICIES_FILE, POLICY_ENTRY_LENGTH};
use karyos_archive::integrity::time::{Requirement, Verdict};
use karyos_archive::integrity::time_evidence;
use karyos_archive::integrity::trust::{
    HEADS_FILE, KEYS_FILE, REGISTRY_ENTRY_LENGTH, RegistryEntry, SIGNED_HEAD_LENGTH, SignedHead,
};
use karyos_archive::integrity::verify::Outcome;
use karyos_archive::integrity::{SealKind, SealRecord, digest};
use karyos_archive::segment::{SegmentStore, SyncPolicy, recorded_geometry};

use crate::catalog::EXIT_ERROR;
use crate::catalog_verify::{hex32, parse_trust_journals};

/// Why an export or its verification failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportCommandError {
    /// The command line.
    #[error("usage: {0}")]
    Usage(String),
    /// A file could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// The trust file.
    #[error("{0}")]
    Trust(String),
    /// The Archive's files do not hold what the export needs.
    #[error("{0}")]
    Archive(String),
    /// The offline verification refused the export.
    #[error(transparent)]
    Offline(#[from] karyos_archive::integrity::export::offline::OfflineError),
}

/// `export`'s arguments.
#[derive(Debug, Clone, Default)]
struct ExportArgs {
    dir: PathBuf,
    trust: Option<PathBuf>,
    recordings: Vec<u64>,
    anchors: Vec<([u8; 32], PathBuf)>,
    time: bool,
    clock_records: Option<PathBuf>,
    schemas: Vec<(u16, u16, PathBuf)>,
    created_ns: u64,
    out: Option<PathBuf>,
}

fn usage(what: &str) -> ExportCommandError {
    ExportCommandError::Usage(what.to_owned())
}

fn text(value: OsString) -> Result<String, ExportCommandError> {
    value
        .into_string()
        .map_err(|_| usage("an argument is not UTF-8"))
}

fn anchor_arg(value: &str) -> Result<([u8; 32], PathBuf), ExportCommandError> {
    let (location, dir) = value
        .split_once('=')
        .ok_or_else(|| usage("--anchors <hex>=<dir>"))?;
    let location = hex32(location).map_err(|_| usage("--anchors <hex>=<dir>"))?;
    Ok((location, PathBuf::from(dir)))
}

fn parse_export(
    args: impl IntoIterator<Item = OsString>,
) -> Result<ExportArgs, ExportCommandError> {
    let mut parsed = ExportArgs::default();
    let mut dir = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = text(arg)?;
        let mut value = || {
            args.next()
                .map(text)
                .transpose()?
                .ok_or_else(|| usage("an option needs its value"))
        };
        match arg.as_str() {
            "--trust" => parsed.trust = Some(PathBuf::from(value()?)),
            "--recording" => parsed
                .recordings
                .push(value()?.parse().map_err(|_| usage("--recording <id>"))?),
            "--anchors" => parsed.anchors.push(anchor_arg(&value()?)?),
            "--time" => parsed.time = true,
            "--clock-records" => parsed.clock_records = Some(PathBuf::from(value()?)),
            "--schema" => {
                let value = value()?;
                let bad = || usage("--schema <id>:<version>=<file>");
                let (ids, file) = value.split_once('=').ok_or_else(bad)?;
                let (id, version) = ids.split_once(':').ok_or_else(bad)?;
                parsed.schemas.push((
                    id.parse().map_err(|_| bad())?,
                    version.parse().map_err(|_| bad())?,
                    PathBuf::from(file),
                ));
            }
            "--created-ns" => {
                parsed.created_ns = value()?.parse().map_err(|_| usage("--created-ns <ns>"))?;
            }
            "--out" => parsed.out = Some(PathBuf::from(value()?)),
            other if dir.is_none() && !other.starts_with("--") => dir = Some(PathBuf::from(other)),
            _ => return Err(usage("unknown option (karyos-catalog --help)")),
        }
    }
    parsed.dir = dir.ok_or_else(|| usage("export <archive> ..."))?;
    if parsed.recordings.is_empty() {
        return Err(usage("export needs at least one --recording"));
    }
    if parsed.trust.is_none() || parsed.out.is_none() {
        return Err(usage("export needs --trust and --out"));
    }
    Ok(parsed)
}

fn read_trust(
    path: &PathBuf,
) -> Result<
    (
        karyos_archive::integrity::trust::TrustRoot,
        karyos_archive::integrity::anchor::Externality,
        u64,
        Option<u64>,
    ),
    ExportCommandError,
> {
    let content = std::fs::read_to_string(path).map_err(|source| ExportCommandError::Io {
        path: path.clone(),
        source,
    })?;
    parse_trust_journals(&content).map_err(|error| ExportCommandError::Trust(error.to_string()))
}

fn stores(anchors: &[([u8; 32], PathBuf)]) -> Result<Vec<StoredAnchors>, ExportCommandError> {
    let mut disk = ReadOnly(StdDisk);
    anchors
        .iter()
        .map(|(location, dir)| {
            let ledger = dir.join(ANCHOR_FILE);
            disk.open_read(&ledger)
                .map_err(|source| ExportCommandError::Io {
                    path: ledger,
                    source,
                })?;
            let entries: Vec<[u8; ANCHOR_LENGTH]> = read_entries(&mut disk, dir, ANCHOR_FILE)
                .map_err(|source| ExportCommandError::Io {
                    path: dir.clone(),
                    source,
                })?;
            Ok(StoredAnchors::new(*location, entries))
        })
        .collect()
}

/// One journal of `dir`, carried from its genesis through `last`: its
/// records, the registry rows its key registry seals commit, and its heads
/// and the stores' anchors for it, up to `last`.
fn journal(
    dir: &std::path::Path,
    id: u64,
    role: u16,
    stores: &[StoredAnchors],
    last_needed: impl Fn(&[SealRecord], &[Anchor]) -> Option<u64>,
) -> Result<JournalExport, ExportCommandError> {
    let at = |source| ExportCommandError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut disk = ReadOnly(StdDisk);
    let (records, _) = read_records(&mut disk, dir).map_err(at)?;
    let anchors: Vec<Anchor> = stores
        .iter()
        .flat_map(StoredAnchors::anchors)
        .filter(|anchor| anchor.signed.head.journal_id == id)
        .collect();
    let last = last_needed(&records, &anchors).unwrap_or(0);
    let records: Vec<SealRecord> = records
        .into_iter()
        .take_while(|record| record.counter <= last)
        .collect();
    let keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]> =
        read_entries(&mut disk, dir, KEYS_FILE).map_err(at)?;
    let mut registry = Vec::new();
    let mut entries = keys.iter();
    for seal in records
        .iter()
        .filter(|record| record.kind == SealKind::KeyRegistry)
    {
        // The row each seal commits, in order; a written but uncommitted
        // row in between is skipped, as the registry's own replay does.
        let row = entries
            .find(|row| digest(row.as_slice()) == seal.content)
            .ok_or_else(|| {
                ExportCommandError::Archive(format!("journal {id}: a registry row is missing"))
            })?;
        registry.push(RegistryEntry::decode(row).map_err(|_| {
            ExportCommandError::Archive(format!("journal {id}: a registry row does not decode"))
        })?);
    }
    let heads: Vec<[u8; SIGNED_HEAD_LENGTH]> =
        read_entries(&mut disk, dir, HEADS_FILE).map_err(at)?;
    let heads = heads
        .iter()
        .filter_map(|bytes| SignedHead::decode(bytes).ok())
        .filter(|head| head.head.journal_id == id && head.head.counter <= last)
        .collect();
    let anchors = anchors
        .into_iter()
        .filter(|anchor| anchor.signed.head.counter <= last)
        .collect();
    Ok(JournalExport {
        id,
        role,
        records,
        heads,
        anchors,
        registry,
    })
}

/// The latest head the anchors cover.
fn anchored(anchors: &[Anchor]) -> Option<u64> {
    anchors
        .iter()
        .map(|anchor| anchor.signed.head.counter)
        .max()
}

/// Gathers an export of `args` from the Archive's files.
fn gather(args: &ExportArgs) -> Result<ExportContents, ExportCommandError> {
    let trust_path = args.trust.clone().unwrap_or_default();
    let (trust, _, journal_id, time_journal) = read_trust(&trust_path)?;
    let stores = stores(&args.anchors)?;
    let exported: BTreeSet<u64> = args.recordings.iter().copied().collect();
    let archive = journal(&args.dir, journal_id, 1, &stores, |records, anchors| {
        let sealing = records
            .iter()
            .filter(|record| record.kind.is_range() && exported.contains(&record.subject))
            .map(|record| record.counter)
            .max();
        sealing.max(anchored(anchors))
    })?;
    let listing = list(ReadOnly(StdDisk), &args.dir)
        .map_err(|error| ExportCommandError::Archive(error.to_string()))?;
    let mut recordings = Vec::new();
    for id in &args.recordings {
        // The catalog's metadata when it holds the recording; the store's
        // own recorded geometry opens it either way, as verify does.
        let recording = listing
            .recordings
            .iter()
            .find(|recording| recording.id == *id);
        let geometry = recorded_geometry(&mut ReadOnly(StdDisk), &args.dir, *id)
            .map_err(|error| ExportCommandError::Archive(format!("recording {id}: {error}")))?
            .ok_or_else(|| ExportCommandError::Archive(format!("recording {id} has no segment")))?;
        let ranges: Vec<&SealRecord> = archive
            .records
            .iter()
            .filter(|record| record.kind.is_range() && record.subject == *id)
            .collect();
        let start = ranges
            .iter()
            .map(|record| record.start)
            .min()
            .or_else(|| recording.map(|recording| recording.start))
            .unwrap_or(0);
        let end = ranges
            .iter()
            .map(|record| record.end)
            .max()
            .unwrap_or(start);
        let mut store = SegmentStore::open_verified(
            ReadOnly(StdDisk),
            &args.dir,
            *id,
            geometry,
            SyncPolicy::None,
        )
        .map_err(|error| ExportCommandError::Archive(format!("recording {id}: {error}")))?;
        let length = usize::try_from(end.saturating_sub(start))
            .map_err(|_| ExportCommandError::Archive(format!("recording {id} is too long")))?;
        let mut bytes = vec![0u8; length];
        store
            .read(start, &mut bytes)
            .map_err(|error| ExportCommandError::Archive(format!("recording {id}: {error}")))?;
        recordings.push(RecordingExport {
            recording: *id,
            start,
            segment_length: geometry.segment_length(),
            stream_id: recording.map_or(0, |recording| recording.stream_id),
            session_id: recording.map_or(0, |recording| recording.session_id),
            initial_term_id: recording.map_or(0, |recording| recording.format.initial_term_id),
            mtu: recording.map_or(0, |recording| recording.format.mtu.get()),
            bytes,
        });
    }
    // The policy versions and bindings the carried chain seals.
    let mut disk = ReadOnly(StdDisk);
    let book: Vec<[u8; POLICY_ENTRY_LENGTH]> = read_entries(&mut disk, &args.dir, POLICIES_FILE)
        .map_err(|source| ExportCommandError::Io {
            path: args.dir.clone(),
            source,
        })?;
    let mut policies = Vec::new();
    let mut bindings = Vec::new();
    for record in &archive.records {
        match record.kind {
            SealKind::Policy => {
                if let Some(canonical) = book.iter().find_map(|entry| {
                    let canonical: [u8; 30] = entry.get(1..31)?.try_into().ok()?;
                    (entry.first() == Some(&1) && digest(&canonical) == record.content)
                        .then_some(canonical)
                }) {
                    policies.push(canonical);
                }
            }
            SealKind::Catalog if record.subject == u64::MAX => {
                if let Some(entry) = book.iter().find(|entry| {
                    entry.first() == Some(&2) && digest(entry.as_slice()) == record.content
                }) {
                    bindings.push(*entry);
                }
            }
            _ => {}
        }
    }
    let mut journals = vec![archive];
    let mut time_evidence = None;
    if args.time {
        let id = time_journal.ok_or_else(|| {
            ExportCommandError::Trust("--time needs the trust file's time-journal line".to_owned())
        })?;
        let dir = time_evidence::entries_dir(&args.dir);
        let entries_journal = journal(&dir, id, 2, &stores, |records, _| {
            records.last().map(|record| record.counter)
        })?;
        let entries = time_evidence::read_sealed(StdDisk, &args.dir)
            .map_err(|error| ExportCommandError::Archive(error.to_string()))?;
        journals.push(entries_journal);
        time_evidence = Some((id, entries));
    }
    let clock_records = match &args.clock_records {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|source| ExportCommandError::Io {
                path: path.clone(),
                source,
            })?;
            let (records, rest) = bytes.as_chunks::<144>();
            if !rest.is_empty() {
                return Err(ExportCommandError::Archive(
                    "the clock records file is not whole 144 byte records".to_owned(),
                ));
            }
            records
                .iter()
                .map(|record| {
                    let mut words = [0u64; 18];
                    for (word, bytes) in words.iter_mut().zip(record.as_chunks::<8>().0) {
                        *word = u64::from_le_bytes(*bytes);
                    }
                    words
                })
                .collect()
        }
        None => Vec::new(),
    };
    Ok(ExportContents {
        archive_id: trust.archive_id,
        created_utc_ns: args.created_ns,
        journals,
        recordings,
        codec_schemas: args
            .schemas
            .iter()
            .map(|(id, version, path)| {
                std::fs::read(path)
                    .map(|bytes| (*id, *version, bytes))
                    .map_err(|source| ExportCommandError::Io {
                        path: path.clone(),
                        source,
                    })
            })
            .collect::<Result<_, _>>()?,
        clock_records,
        time_evidence,
        policies,
        bindings,
    })
}

/// Runs `karyos-catalog export`.
pub fn run_export(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> u8 {
    let result = parse_export(args).and_then(|args| {
        let contents = gather(&args)?;
        let bytes =
            assemble(&contents).map_err(|error| ExportCommandError::Archive(error.to_string()))?;
        let out = args.out.clone().unwrap_or_default();
        std::fs::write(&out, &bytes).map_err(|source| ExportCommandError::Io {
            path: out.clone(),
            source,
        })?;
        Ok((out, bytes.len()))
    });
    match result {
        Ok((out, length)) => {
            let _ = writeln!(stdout, "exported {length} bytes to {}", out.display());
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "karyos-catalog: {error}");
            EXIT_ERROR
        }
    }
}

/// `verify-export`'s arguments.
#[derive(Debug, Default)]
struct VerifyExportArgs {
    file: Option<PathBuf>,
    trust: Option<PathBuf>,
    anchors: Vec<([u8; 32], PathBuf)>,
    requirement: Option<Requirement>,
    json: bool,
}

fn parse_verify_export(
    args: impl IntoIterator<Item = OsString>,
) -> Result<VerifyExportArgs, ExportCommandError> {
    let mut parsed = VerifyExportArgs::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = text(arg)?;
        let mut value = || {
            args.next()
                .map(text)
                .transpose()?
                .ok_or_else(|| usage("an option needs its value"))
        };
        match arg.as_str() {
            "--trust" => parsed.trust = Some(PathBuf::from(value()?)),
            "--anchors" => parsed.anchors.push(anchor_arg(&value()?)?),
            "--time-requirement" => {
                let value = value()?;
                let (max, granularity) = value
                    .split_once(':')
                    .ok_or_else(|| usage("--time-requirement <max_ns>:<granularity_ns>"))?;
                parsed.requirement = Some(Requirement {
                    max_divergence_ns: max.parse().map_err(|_| usage("--time-requirement"))?,
                    max_granularity_ns: granularity
                        .parse()
                        .map_err(|_| usage("--time-requirement"))?,
                });
            }
            "--json" => parsed.json = true,
            other if parsed.file.is_none() && !other.starts_with("--") => {
                parsed.file = Some(PathBuf::from(other));
            }
            _ => return Err(usage("unknown option (karyos-catalog --help)")),
        }
    }
    if parsed.file.is_none() || parsed.trust.is_none() {
        return Err(usage("verify-export <file> --trust <file>"));
    }
    Ok(parsed)
}

const fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Verified => "verified",
        Outcome::BeyondAnchor => "beyond_anchor",
        Outcome::Inconsistent => "inconsistent",
        Outcome::Unsealed => "unsealed",
        Outcome::Purged => "purged",
        _ => "other",
    }
}

const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Met => "met",
        Verdict::NoEvidence => "no_evidence",
        Verdict::NotMet => "not_met",
    }
}

/// Runs `karyos-catalog verify-export`: 0 when every range verifies, 1
/// when any does not, the error status when the export is refused.
pub fn run_verify_export(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> u8 {
    let result = parse_verify_export(args).and_then(|args| {
        let file = args.file.clone().unwrap_or_default();
        let bytes = std::fs::read(&file).map_err(|source| ExportCommandError::Io {
            path: file.clone(),
            source,
        })?;
        let (trust, externality, journal, time_journal) =
            read_trust(&args.trust.clone().unwrap_or_default())?;
        let stores = stores(&args.anchors)?;
        let mut journals = vec![(journal, Role::Archive)];
        if let Some(time_journal) = time_journal {
            journals.push((time_journal, Role::TimeEvidence));
        }
        let report = verify_export(
            &bytes,
            &OfflineTrust {
                trust: &trust,
                journals: &journals,
                stores: &stores,
                externality: &externality,
                requirement: args.requirement,
            },
        )?;
        Ok((report, args.json))
    });
    match result {
        Ok((report, json)) => {
            let mut all = true;
            let mut lines = Vec::new();
            for (id, _, verification) in &report.journals {
                for range in &verification.ranges {
                    all &= range.outcome == Outcome::Verified;
                    lines.push((
                        *id,
                        range.recording,
                        range.start,
                        range.end,
                        outcome_name(range.outcome),
                    ));
                }
            }
            if json {
                let ranges: Vec<String> = lines
                    .iter()
                    .map(|(journal, recording, start, end, outcome)| {
                        format!(
                            "{{\"journal\":{journal},\"recording\":{recording},\"start\":{start},\"end\":{end},\"outcome\":\"{outcome}\"}}"
                        )
                    })
                    .collect();
                let time: Vec<String> = report
                    .time
                    .iter()
                    .map(|(recording, verdict)| {
                        format!(
                            "{{\"recording\":{recording},\"verdict\":\"{}\"}}",
                            verdict_name(*verdict)
                        )
                    })
                    .collect();
                let _ = writeln!(
                    stdout,
                    "{{\"ranges\":[{}],\"time\":[{}]}}",
                    ranges.join(","),
                    time.join(",")
                );
            } else {
                for (journal, recording, start, end, outcome) in &lines {
                    let _ = writeln!(
                        stdout,
                        "journal {journal} recording {recording} [{start}, {end}) {outcome}"
                    );
                }
                for (recording, finding) in &report.policies {
                    let _ = writeln!(stdout, "policy recording {recording} {finding:?}");
                }
                for (recording, verdict) in &report.time {
                    let _ = writeln!(
                        stdout,
                        "time recording {recording} {}",
                        verdict_name(*verdict)
                    );
                }
            }
            u8::from(!all)
        }
        Err(error) => {
            let _ = writeln!(stderr, "karyos-catalog: {error}");
            EXIT_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
