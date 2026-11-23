// SPDX-License-Identifier: Apache-2.0
//! Verifying an export offline (ADR-0103; quantstratum-docs:
//! karyos/design/archive-export.md section 5; karyos#668): with the
//! external trust only, and no Archive present.
//!
//! Each carried journal is verified by the online verifier
//! ([`super::super::verify::verify`]) over the export's own records, so
//! the integrity outcomes are the online ones. Around it, the rules only
//! an export needs: the reciprocal row checks against their seals
//! (`Incomplete`), the anchored run (only records up to the latest trusted
//! anchored head grant trust; retirements and revocations always count),
//! policy applicability and the time verdict.

use std::collections::BTreeMap;

use super::super::anchor::{ANCHOR_LENGTH, Anchor, AnchorEvidence, Externality};
use super::super::time::{self, Requirement, Verdict};
use super::super::time_evidence::{ENTRIES, ENTRY_LENGTH, Entry};
use super::super::trust::{REGISTRY_ENTRY_LENGTH, SIGNED_HEAD_LENGTH, TrustRoot};
use super::super::verify::{Evidence, RangeBytes, Verification, verify};
use super::super::{SealKind, SealRecord, digest};
use super::{Export, ExportError, Section, SectionKind, decode};

/// A journal's role (design section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// The Archive's integrity journal.
    Archive,
    /// A time evidence entries' journal.
    TimeEvidence,
    /// A group journal directory's integrity journal.
    Group,
}

impl Role {
    const fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::Archive,
            2 => Self::TimeEvidence,
            3 => Self::Group,
            _ => return None,
        })
    }
}

/// What the verifier is given outside the export.
#[derive(Debug, Clone, Copy)]
pub struct OfflineTrust<'a> {
    /// The trust root: the Archive's identity and its authorities.
    pub trust: &'a TrustRoot,
    /// The journal identities the trust file names, with their roles.
    pub journals: &'a [(u64, Role)],
    /// The trusted anchor stores' own evidence.
    pub stores: &'a dyn AnchorEvidence,
    /// What counts as external.
    pub externality: &'a Externality,
    /// The operator's time requirement; `None` evaluates no time verdict.
    pub requirement: Option<Requirement>,
}

/// Why an export cannot be verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OfflineError {
    /// The file itself is refused.
    #[error(transparent)]
    Container(#[from] ExportError),
    /// The export is not of the trusted Archive, or names a journal the
    /// trust does not, or in another role.
    #[error("the export does not match the trust: {0}")]
    Trust(&'static str),
    /// A row is missing against its seal, or a row no seal commits.
    #[error("the export is incomplete: {what} of journal {journal}")]
    Incomplete {
        /// The journal.
        journal: u64,
        /// What is missing.
        what: &'static str,
    },
    /// A record of a section does not decode.
    #[error("a record of journal {journal} does not decode: {what}")]
    Malformed {
        /// The journal, 0 for none.
        journal: u64,
        /// The section.
        what: &'static str,
    },
}

/// A recording's policy, as the export proves it (design section 5,
/// step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyFinding {
    /// Proven: a recording binding in the anchored run names it, and the
    /// policy's latest version in the run.
    Proven {
        /// The policy.
        policy: u64,
        /// Its version.
        version: u64,
    },
    /// Only a class binding could apply: not proven in version 1.
    Unproven,
    /// No binding names it.
    None,
}

/// What an export proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineReport {
    /// Each journal's verification, in the export's order.
    pub journals: Vec<(u64, Role, Verification)>,
    /// Each exported recording's policy.
    pub policies: Vec<(u64, PolicyFinding)>,
    /// Each exported recording's time verdict, when a requirement is given.
    pub time: Vec<(u64, Verdict)>,
}

/// One journal's sections.
#[derive(Debug, Default)]
struct Group<'a> {
    role: Option<Role>,
    seals: Option<&'a Section>,
    heads: Option<&'a Section>,
    anchors: Option<&'a Section>,
    registry: Option<&'a Section>,
}

fn rows<const N: usize>(section: Option<&Section>) -> Vec<[u8; N]> {
    section
        .map(|section| section.body.as_chunks::<N>().0.to_vec())
        .unwrap_or_default()
}

/// Verifies `bytes`, an export, offline under `trust`.
///
/// # Errors
///
/// [`OfflineError`].
pub fn verify_export(
    bytes: &[u8],
    trust: &OfflineTrust<'_>,
) -> Result<OfflineReport, OfflineError> {
    let export = decode(bytes)?;
    if export.archive_id != trust.trust.archive_id {
        return Err(OfflineError::Trust("another Archive's export"));
    }
    let (groups, rest) = split(&export)?;
    for (id, group) in &groups {
        let role = group
            .role
            .ok_or(OfflineError::Trust("a journal without its role"))?;
        if !trust.journals.contains(&(*id, role)) {
            return Err(OfflineError::Trust("a journal the trust does not name"));
        }
    }
    let manifest = manifest(rest.get(&SectionKind::Manifest).copied())?;
    let frames = frames(rest.get(&SectionKind::Frames).copied())?;
    let written: Vec<(u64, u64)> = manifest
        .iter()
        .map(|row| (row.recording, row.end))
        .collect();
    let mut journals = Vec::new();
    let mut archive_run: Option<(Vec<SealRecord>, Option<usize>)> = None;
    let mut entries_runs: Vec<(Vec<SealRecord>, Option<usize>)> = Vec::new();
    for (id, group) in &groups {
        let role = group.role.unwrap_or(Role::Group);
        let records = seal_records(*id, group.seals)?;
        let registry = rows::<REGISTRY_ENTRY_LENGTH>(group.registry);
        reciprocal_registry(*id, &records, &registry)?;
        let heads = rows::<SIGNED_HEAD_LENGTH>(group.heads);
        let anchors = rows::<ANCHOR_LENGTH>(group.anchors)
            .iter()
            .map(Anchor::decode)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| OfflineError::Malformed {
                journal: *id,
                what: "an anchor",
            })?;
        let evidence = Evidence {
            records: &records,
            journal_fault: None,
            journal_id: *id,
            trust: Some(trust.trust),
            registry: &registry,
            heads: &heads,
            anchors: &anchors,
            anchor_faults: 0,
            stores: trust.stores,
            externality: trust.externality,
            written: if role == Role::Archive { &written } else { &[] },
        };
        // A time evidence journal seals the entries' store, whose bytes
        // are the `TimeEvidence` section's; every other journal seals
        // recordings, read from `Frames` (#1183 review).
        let store: Vec<(u64, u64, Vec<u8>)> = rest
            .get(&SectionKind::TimeEvidence)
            .map(|section| vec![(ENTRIES, 0, section.body.clone())])
            .unwrap_or_default();
        let source = if role == Role::TimeEvidence {
            &store
        } else {
            &frames
        };
        let verification = verify(&evidence, |recording, start, end| {
            read(source, recording, start, end)
        });
        // Only the verified positional prefix counts: a record from a
        // broken suffix never does, whatever counter it declares (#1183
        // review). The run is a position in that prefix.
        let prefix = verification
            .journal_break
            .and_then(|at| usize::try_from(at).ok())
            .unwrap_or(records.len())
            .min(records.len());
        let mut records = records;
        records.truncate(prefix);
        let run = verification
            .coverage
            .anchored_through
            .and_then(|at| usize::try_from(at).ok())
            .filter(|at| *at < prefix);
        match role {
            Role::Archive => archive_run = Some((records, run)),
            Role::TimeEvidence => entries_runs.push((records, run)),
            Role::Group => {}
        }
        journals.push((*id, role, verification));
    }
    let policies = match archive_run.as_ref() {
        Some((records, run)) => policies(
            records,
            *run,
            rest.get(&SectionKind::Policies).copied(),
            rest.get(&SectionKind::PolicyBindings).copied(),
            &manifest,
        )?,
        None => Vec::new(),
    };
    let entries = time_entries(
        &groups,
        &entries_runs,
        rest.get(&SectionKind::TimeEvidence).copied(),
    )?;
    let time = match trust.requirement {
        Some(requirement) => manifest
            .iter()
            .map(|row| {
                (
                    row.recording,
                    time_verdict(
                        row,
                        &entries,
                        &clock_digests(rest.get(&SectionKind::ClockRecords).copied()),
                        &requirement,
                    ),
                )
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(OfflineReport {
        journals,
        policies,
        time,
    })
}

type Groups<'a> = Vec<(u64, Group<'a>)>;
type Rest<'a> = BTreeMap<SectionKind, &'a Section>;

/// The journal groups, in order, and the other sections by kind.
fn split(export: &Export) -> Result<(Groups<'_>, Rest<'_>), OfflineError> {
    let mut groups: Groups<'_> = Vec::new();
    let mut rest: Rest<'_> = BTreeMap::new();
    for section in &export.sections {
        if !section.kind.per_journal() {
            rest.insert(section.kind, section);
            continue;
        }
        if section.kind == SectionKind::Journal {
            let role = section
                .body
                .first_chunk::<2>()
                .map(|code| u16::from_le_bytes(*code))
                .and_then(Role::from_code);
            groups.push((
                section.journal,
                Group {
                    role,
                    ..Group::default()
                },
            ));
            continue;
        }
        let Some((_, group)) = groups.last_mut() else {
            return Err(OfflineError::Container(ExportError::Order { section: 0 }));
        };
        let slot = match section.kind {
            SectionKind::Seals => &mut group.seals,
            SectionKind::SignedHeads => &mut group.heads,
            SectionKind::Anchors => &mut group.anchors,
            _ => &mut group.registry,
        };
        *slot = Some(section);
    }
    Ok((groups, rest))
}

fn seal_records(journal: u64, seals: Option<&Section>) -> Result<Vec<SealRecord>, OfflineError> {
    seals
        .map(|section| section.body.as_chunks::<112>().0)
        .unwrap_or_default()
        .iter()
        .map(|row| SealRecord::decode(row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OfflineError::Malformed {
            journal,
            what: "a seal record",
        })
}

/// Exactly one registry row per key registry seal, in order, each its
/// seal's digest (design section 3.5): retirements and revocations after
/// the anchored run count too, so every kind 6 seal carried is checked.
fn reciprocal_registry(
    journal: u64,
    records: &[SealRecord],
    registry: &[[u8; REGISTRY_ENTRY_LENGTH]],
) -> Result<(), OfflineError> {
    let seals: Vec<&SealRecord> = records
        .iter()
        .filter(|record| record.kind == SealKind::KeyRegistry)
        .collect();
    let matches = seals.len() == registry.len()
        && seals
            .iter()
            .zip(registry)
            .all(|(seal, row)| seal.content == digest(row));
    if matches {
        Ok(())
    } else {
        Err(OfflineError::Incomplete {
            journal,
            what: "the key registry",
        })
    }
}

/// A manifest row (design section 3.6).
#[derive(Debug, Clone, Copy)]
pub(super) struct ManifestRow {
    pub(super) recording: u64,
    pub(super) start: u64,
    pub(super) end: u64,
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<8>())
        .map_or(0, |b| u64::from_le_bytes(*b))
}

fn manifest(section: Option<&Section>) -> Result<Vec<ManifestRow>, OfflineError> {
    Ok(rows::<64>(section)
        .iter()
        .map(|row| ManifestRow {
            recording: u64_at(row, 0),
            start: u64_at(row, 8),
            end: u64_at(row, 16),
        })
        .collect())
}

/// The `Frames` chunks: recording, start, bytes.
fn frames(section: Option<&Section>) -> Result<Vec<(u64, u64, Vec<u8>)>, OfflineError> {
    let Some(section) = section else {
        return Ok(Vec::new());
    };
    let body = &section.body;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < body.len() {
        let recording = u64_at(body, at);
        let start = u64_at(body, at.saturating_add(8));
        let length = usize::try_from(u64_at(body, at.saturating_add(16))).map_err(|_| {
            OfflineError::Malformed {
                journal: 0,
                what: "a frames chunk",
            }
        })?;
        let from = at.saturating_add(24);
        let bytes = body
            .get(from..from.saturating_add(length))
            .ok_or(OfflineError::Malformed {
                journal: 0,
                what: "a frames chunk",
            })?;
        out.push((recording, start, bytes.to_vec()));
        at = from.saturating_add(length.saturating_add(7) / 8 * 8);
    }
    Ok(out)
}

/// The bytes of `recording`'s `[start, end)` from the chunks.
fn read(frames: &[(u64, u64, Vec<u8>)], recording: u64, start: u64, end: u64) -> RangeBytes {
    let mut out = Vec::new();
    let mut at = start;
    while at < end {
        let Some((_, from, bytes)) = frames.iter().find(|(id, from, bytes)| {
            *id == recording
                && *from <= at
                && at < from.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        }) else {
            return RangeBytes::Missing;
        };
        let offset = usize::try_from(at.saturating_sub(*from)).unwrap_or(usize::MAX);
        let take = usize::try_from(end.saturating_sub(at))
            .unwrap_or(usize::MAX)
            .min(bytes.len().saturating_sub(offset));
        let Some(part) = bytes.get(offset..offset.saturating_add(take)) else {
            return RangeBytes::Missing;
        };
        out.extend_from_slice(part);
        at = at.saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
        if take == 0 {
            return RangeBytes::Missing;
        }
    }
    RangeBytes::Bytes(out)
}

/// The policy book's subject in the chain.
const POLICY_BOOK: u64 = u64::MAX;

/// Policies and bindings, replayed reciprocally over the Archive journal's
/// anchored run (design section 5, step 7).
fn policies(
    records: &[SealRecord],
    run: Option<usize>,
    versions: Option<&Section>,
    bindings: Option<&Section>,
    manifest: &[ManifestRow],
) -> Result<Vec<(u64, PolicyFinding)>, OfflineError> {
    // By position in the verified prefix, never by declared counter.
    let in_run_records: Vec<&SealRecord> = run
        .map(|run| records.iter().take(run.saturating_add(1)).collect())
        .unwrap_or_default();
    let version_rows = rows::<32>(versions);
    let binding_rows = rows::<64>(bindings);
    let version_seals: Vec<&SealRecord> = in_run_records
        .iter()
        .copied()
        .filter(|record| record.kind == SealKind::Policy)
        .collect();
    let binding_seals: Vec<&SealRecord> = in_run_records
        .iter()
        .copied()
        .filter(|record| record.kind == SealKind::Catalog && record.subject == POLICY_BOOK)
        .collect();
    let incomplete = |what| OfflineError::Incomplete { journal: 0, what };
    // Each seal in the run has its row, and the rows are those seals'.
    let mut in_force: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for seal in &version_seals {
        let row = version_rows
            .iter()
            .find(|row| {
                row.get(..30)
                    .is_some_and(|canonical| digest(canonical) == seal.content)
            })
            .ok_or_else(|| incomplete("a policy version"))?;
        let policy = u64_at(row, 0);
        let version = u64_at(row, 8);
        in_force.insert(policy, (version, seal.counter));
    }
    if version_rows.len() != version_seals.len() {
        return Err(incomplete("a policy version"));
    }
    let mut bound: BTreeMap<u64, u64> = BTreeMap::new();
    let mut classes = false;
    for seal in &binding_seals {
        let row = binding_rows
            .iter()
            .find(|row| digest(row.as_slice()) == seal.content)
            .ok_or_else(|| incomplete("a policy binding"))?;
        match row.get(1) {
            Some(1) => {
                bound.insert(u64_at(row, 16), u64_at(row, 8));
            }
            _ => classes = true,
        }
    }
    if binding_rows.len() != binding_seals.len() {
        return Err(incomplete("a policy binding"));
    }
    Ok(manifest
        .iter()
        .map(|row| {
            let finding = match bound.get(&row.recording) {
                Some(policy) => in_force
                    .get(policy)
                    .map_or(PolicyFinding::None, |(version, _)| PolicyFinding::Proven {
                        policy: *policy,
                        version: *version,
                    }),
                None if classes => PolicyFinding::Unproven,
                None => PolicyFinding::None,
            };
            (row.recording, finding)
        })
        .collect())
}

/// The time evidence entries that count: the entries' store checked
/// complete against its journal's seals, each entry counting only if its
/// seal lies in the journal's anchored run (design section 5, step 6).
fn time_entries(
    groups: &Groups<'_>,
    runs: &[(Vec<SealRecord>, Option<usize>)],
    section: Option<&Section>,
) -> Result<Vec<Entry>, OfflineError> {
    let journal = groups
        .iter()
        .find(|(_, group)| group.role == Some(Role::TimeEvidence))
        .map_or(0, |(id, _)| *id);
    let store: &[u8] = section.map_or(&[], |section| section.body.as_slice());
    let incomplete = || OfflineError::Incomplete {
        journal,
        what: "the time evidence entries",
    };
    let Some((records, run)) = runs.first() else {
        // Entries with no journal to prove them (#1183 review).
        return if store.is_empty() {
            Ok(Vec::new())
        } else {
            Err(incomplete())
        };
    };
    // The entries' seals by position, each with whether it is in the run.
    let mut seals: Vec<(&SealRecord, bool)> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record.kind.is_range() && record.subject == ENTRIES)
        .map(|(position, record)| (record, run.is_some_and(|run| position <= run)))
        .collect();
    seals.sort_by_key(|(seal, _)| seal.start);
    // The seals tile the store from zero, contiguous, each digest its
    // bytes': no row unsealed before, between or after them (#1183 review).
    let mut at = 0u64;
    for (seal, _) in &seals {
        if seal.start != at {
            return Err(incomplete());
        }
        let (Ok(start), Ok(end)) = (usize::try_from(seal.start), usize::try_from(seal.end)) else {
            return Err(incomplete());
        };
        let bytes = store.get(start..end).ok_or_else(incomplete)?;
        if digest(bytes) != seal.content {
            return Err(incomplete());
        }
        at = seal.end;
    }
    if u64::try_from(store.len()).unwrap_or(u64::MAX) != at {
        return Err(incomplete());
    }
    // Entries and seals walked together, both in store order.
    let length = u64::try_from(ENTRY_LENGTH).unwrap_or(u64::MAX);
    let mut out = Vec::new();
    let mut next = seals.iter().peekable();
    for (index, row) in store.as_chunks::<ENTRY_LENGTH>().0.iter().enumerate() {
        let from = u64::try_from(index)
            .unwrap_or(u64::MAX)
            .saturating_mul(length);
        let to = from.saturating_add(length);
        while next.peek().is_some_and(|(seal, _)| seal.end <= from) {
            let _ = next.next();
        }
        let counts = next
            .peek()
            .is_some_and(|(seal, in_run)| *in_run && seal.start <= from && to <= seal.end);
        if counts {
            out.push(Entry::decode(row).map_err(|_| OfflineError::Malformed {
                journal,
                what: "a time evidence entry",
            })?);
        }
    }
    Ok(out)
}

/// The SHA-256 of each carried clock record.
fn clock_digests(section: Option<&Section>) -> Vec<super::super::Digest> {
    rows::<144>(section).iter().map(|row| digest(row)).collect()
}

/// A recording's time verdict: `met` only with at least one clock whose
/// counting entries cover its whole exported range, each `met` with its
/// cited records carried; `no_evidence` for no clock or a gap.
pub(super) fn time_verdict(
    row: &ManifestRow,
    entries: &[Entry],
    clocks: &[super::super::Digest],
    requirement: &Requirement,
) -> Verdict {
    // Only entries over the exported interval (#1183 review).
    let mine: Vec<&Entry> = entries
        .iter()
        .filter(|entry| {
            entry.recording == row.recording && entry.start < row.end && row.start < entry.end
        })
        .collect();
    if mine.is_empty() {
        return Verdict::NoEvidence;
    }
    let mut by_clock: BTreeMap<[u64; 5], Vec<&Entry>> = BTreeMap::new();
    for entry in mine {
        by_clock.entry(entry.clock).or_default().push(entry);
    }
    let mut verdicts = Vec::new();
    for (_, mut entries) in by_clock {
        entries.sort_by_key(|entry| entry.start);
        let mut at = row.start;
        for entry in &entries {
            if entry.start > at {
                break;
            }
            at = at.max(entry.end);
        }
        if at < row.end {
            verdicts.push(Verdict::NoEvidence);
            continue;
        }
        for entry in entries {
            let cited = (entry.calibration == [0; 32] || clocks.contains(&entry.calibration))
                && (entry.utc_reference == [0; 32] || clocks.contains(&entry.utc_reference));
            verdicts.push(if cited {
                entry.verdict(requirement)
            } else {
                Verdict::NoEvidence
            });
        }
    }
    time::reduce(&verdicts, Some(requirement))
        .map_or(Verdict::NoEvidence, |combined| combined.verdict)
}
