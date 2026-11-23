// SPDX-License-Identifier: Apache-2.0
//! Assembling an export (ADR-0103; quantstratum-docs:
//! karyos/design/archive-export.md; karyos#668): the records an exporter
//! gathered, laid out in the design's section 4 order with its pinned
//! readings (section 8): empty sections omitted, one `Frames` chunk per
//! recording, a carried empty `TimeEvidence` only when asked for.

use super::super::Digest;
use super::super::SealRecord;
use super::super::anchor::Anchor;
use super::super::time_evidence::Entry;
use super::super::trust::{RegistryEntry, SignedHead};
use super::{Section, SectionKind, chunk, encode, frames_chunk};

/// One carried journal: its identity, role code (design section 3.1) and
/// records, verbatim.
#[derive(Debug, Clone, Default)]
pub struct JournalExport {
    /// The journal identity.
    pub id: u64,
    /// 1 the Archive's, 2 a time evidence journal, 3 a group directory's.
    pub role: u16,
    /// Its seal records, contiguous, in counter order.
    pub records: Vec<SealRecord>,
    /// Its signed heads.
    pub heads: Vec<SignedHead>,
    /// Its anchors.
    pub anchors: Vec<Anchor>,
    /// Its registry entries, one per key registry seal.
    pub registry: Vec<RegistryEntry>,
}

/// One exported recording and its bytes.
#[derive(Debug, Clone, Default)]
pub struct RecordingExport {
    /// The recording id.
    pub recording: u64,
    /// The first exported position.
    pub start: u64,
    /// The segment length.
    pub segment_length: u64,
    /// Its stream id.
    pub stream_id: i32,
    /// Its session id.
    pub session_id: i32,
    /// Its initial term id.
    pub initial_term_id: i32,
    /// Its MTU.
    pub mtu: u32,
    /// The bytes of `[start, start + len)`.
    pub bytes: Vec<u8>,
}

/// Everything one export carries.
#[derive(Debug, Clone, Default)]
pub struct ExportContents {
    /// The exporting Archive's identity.
    pub archive_id: Digest,
    /// When it was written, UTC ns; 0 not stated.
    pub created_utc_ns: u64,
    /// The journals, the Archive's first.
    pub journals: Vec<JournalExport>,
    /// The recordings.
    pub recordings: Vec<RecordingExport>,
    /// The codec schemas: id, version, bytes.
    pub codec_schemas: Vec<(u16, u16, Vec<u8>)>,
    /// The calibration and UTC reference records, 18 words each.
    pub clock_records: Vec<[u64; 18]>,
    /// The entries' journal and its store, when time evidence is carried;
    /// an empty store is carried as an empty section.
    pub time_evidence: Option<(u64, Vec<Entry>)>,
    /// The policy versions, their 30 canonical bytes.
    pub policies: Vec<[u8; 30]>,
    /// The policy bindings, their 64 bytes.
    pub bindings: Vec<[u8; 64]>,
}

/// Why an export cannot be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssembleError {
    /// A time evidence entry does not encode.
    #[error(transparent)]
    Entry(#[from] super::super::time_evidence::EntryError),
    /// A recording's exported range ends past `u64::MAX`.
    #[error("recording {recording}'s exported range overflows")]
    RangeOverflow {
        /// The recording.
        recording: u64,
    },
}

fn count(rows: usize) -> u64 {
    u64::try_from(rows).unwrap_or(u64::MAX)
}

fn rows<const N: usize>(kind: SectionKind, journal: u64, rows: &[[u8; N]]) -> Option<Section> {
    (!rows.is_empty()).then(|| Section {
        kind,
        journal,
        count: count(rows.len()),
        body: rows.concat(),
    })
}

/// The export's bytes.
///
/// # Errors
///
/// [`AssembleError`].
pub fn assemble(contents: &ExportContents) -> Result<Vec<u8>, AssembleError> {
    let mut sections = Vec::new();
    for journal in &contents.journals {
        let mut row = [0u8; 24];
        let first = journal.records.first().map_or(0, |record| record.counter);
        let last = journal.records.last().map_or(0, |record| record.counter);
        for (slot, byte) in row.iter_mut().zip(
            journal
                .role
                .to_le_bytes()
                .into_iter()
                .chain([0; 6])
                .chain(first.to_le_bytes())
                .chain(last.to_le_bytes()),
        ) {
            *slot = byte;
        }
        sections.push(Section {
            kind: SectionKind::Journal,
            journal: journal.id,
            count: 1,
            body: row.to_vec(),
        });
        let seals: Vec<[u8; 112]> = journal.records.iter().map(SealRecord::encode).collect();
        let heads: Vec<[u8; 184]> = journal.heads.iter().map(SignedHead::encode).collect();
        let anchors: Vec<[u8; 264]> = journal.anchors.iter().map(Anchor::encode).collect();
        let registry: Vec<[u8; 184]> = journal.registry.iter().map(RegistryEntry::encode).collect();
        sections.extend(rows(SectionKind::Seals, journal.id, &seals));
        sections.extend(rows(SectionKind::SignedHeads, journal.id, &heads));
        sections.extend(rows(SectionKind::Anchors, journal.id, &anchors));
        sections.extend(rows(SectionKind::KeyRegistry, journal.id, &registry));
    }
    let manifest: Vec<[u8; 64]> = contents
        .recordings
        .iter()
        .map(|recording| {
            let end = recording
                .start
                .checked_add(count(recording.bytes.len()))
                .ok_or(AssembleError::RangeOverflow {
                    recording: recording.recording,
                })?;
            let mut row = [0u8; 64];
            for (slot, byte) in row.iter_mut().zip(
                recording
                    .recording
                    .to_le_bytes()
                    .into_iter()
                    .chain(recording.start.to_le_bytes())
                    .chain(end.to_le_bytes())
                    .chain(recording.segment_length.to_le_bytes())
                    .chain(recording.stream_id.to_le_bytes())
                    .chain(recording.session_id.to_le_bytes())
                    .chain(recording.initial_term_id.to_le_bytes())
                    .chain(recording.mtu.to_le_bytes()),
            ) {
                *slot = byte;
            }
            Ok(row)
        })
        .collect::<Result<_, AssembleError>>()?;
    sections.extend(rows(SectionKind::Manifest, 0, &manifest));
    if !contents.recordings.is_empty() {
        let body: Vec<u8> = contents
            .recordings
            .iter()
            .flat_map(|recording| {
                frames_chunk(recording.recording, recording.start, &recording.bytes)
            })
            .collect();
        sections.push(Section {
            kind: SectionKind::Frames,
            journal: 0,
            count: count(contents.recordings.len()),
            body,
        });
    }
    if !contents.codec_schemas.is_empty() {
        let body: Vec<u8> = contents
            .codec_schemas
            .iter()
            .flat_map(|(id, version, bytes)| {
                let header: Vec<u8> = id
                    .to_le_bytes()
                    .into_iter()
                    .chain(version.to_le_bytes())
                    .chain([0; 4])
                    .chain(count(bytes.len()).to_le_bytes())
                    .collect();
                chunk(&header, bytes)
            })
            .collect();
        sections.push(Section {
            kind: SectionKind::CodecSchemas,
            journal: 0,
            count: count(contents.codec_schemas.len()),
            body,
        });
    }
    let clocks: Vec<[u8; 144]> = contents
        .clock_records
        .iter()
        .map(|words| {
            let mut row = [0u8; 144];
            for (slot, byte) in row
                .iter_mut()
                .zip(words.iter().flat_map(|word| word.to_le_bytes()))
            {
                *slot = byte;
            }
            row
        })
        .collect();
    sections.extend(rows(SectionKind::ClockRecords, 0, &clocks));
    if let Some((journal, entries)) = &contents.time_evidence {
        let encoded = entries
            .iter()
            .map(Entry::encode)
            .collect::<Result<Vec<_>, _>>()?;
        sections.push(Section {
            kind: SectionKind::TimeEvidence,
            journal: *journal,
            count: count(encoded.len()),
            body: encoded.concat(),
        });
    }
    let policies: Vec<[u8; 32]> = contents
        .policies
        .iter()
        .map(|canonical| {
            let mut row = [0u8; 32];
            for (slot, byte) in row.iter_mut().zip(canonical) {
                *slot = *byte;
            }
            row
        })
        .collect();
    sections.extend(rows(SectionKind::Policies, 0, &policies));
    sections.extend(rows(SectionKind::PolicyBindings, 0, &contents.bindings));
    Ok(encode(
        &contents.archive_id,
        contents.created_utc_ns,
        &sections,
    ))
}
