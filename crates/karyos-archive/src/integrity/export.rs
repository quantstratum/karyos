// SPDX-License-Identifier: Apache-2.0
//! The Archive export file, version 1 (ADR-0103; quantstratum-docs:
//! karyos/design/archive-export.md; karyos#668): its header, typed
//! sections and SHA-256 trailer, encoded and decoded with the typed
//! refusals of the design's section 6.
//!
//! This module is the container only. The records the sections carry
//! travel verbatim and are read by their own decoders (seal records,
//! signed heads, anchors, registry entries, clock records, time evidence
//! entries); what an export proves is the offline verifier's.

use sha2::{Digest as _, Sha256};

use super::Digest;

#[cfg(test)]
mod tests;

/// The file's magic: ASCII `KARYOSX` then a zero byte.
pub const MAGIC: [u8; 8] = *b"KARYOSX\0";
/// The format's version, and every section's.
pub const VERSION: u16 = 1;
/// The header's length.
pub const HEADER_LENGTH: usize = 64;
/// A section header's length.
pub const SECTION_HEADER_LENGTH: usize = 32;
/// The trailer's length: a SHA-256.
pub const TRAILER_LENGTH: usize = 32;

/// A section's kind (design section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SectionKind {
    /// A chained journal: its role and exported counters.
    Journal = 1,
    /// Seal records, 112 bytes each.
    Seals = 2,
    /// Signed heads, 184 bytes each.
    SignedHeads = 3,
    /// Anchors, 264 bytes each.
    Anchors = 4,
    /// Key registry entries, 184 bytes each.
    KeyRegistry = 5,
    /// The exported recordings, 64 bytes each.
    Manifest = 6,
    /// Chunks of recorded bytes.
    Frames = 7,
    /// Chunks of codec schemas.
    CodecSchemas = 8,
    /// Calibration and UTC reference records, 144 bytes each.
    ClockRecords = 9,
    /// Time evidence entries, 200 bytes each.
    TimeEvidence = 10,
    /// Policy versions, 32 bytes each.
    Policies = 11,
    /// Policy bindings, 64 bytes each.
    PolicyBindings = 12,
}

impl SectionKind {
    const fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::Journal,
            2 => Self::Seals,
            3 => Self::SignedHeads,
            4 => Self::Anchors,
            5 => Self::KeyRegistry,
            6 => Self::Manifest,
            7 => Self::Frames,
            8 => Self::CodecSchemas,
            9 => Self::ClockRecords,
            10 => Self::TimeEvidence,
            11 => Self::Policies,
            12 => Self::PolicyBindings,
            _ => return None,
        })
    }

    /// The row length of a row section; `None` for a chunk section.
    #[must_use]
    pub const fn row_length(self) -> Option<usize> {
        match self {
            Self::Journal => Some(24),
            Self::Seals => Some(112),
            Self::SignedHeads | Self::KeyRegistry => Some(184),
            Self::Anchors => Some(264),
            Self::Manifest | Self::PolicyBindings => Some(64),
            Self::ClockRecords => Some(144),
            Self::TimeEvidence => Some(200),
            Self::Policies => Some(32),
            Self::Frames | Self::CodecSchemas => None,
        }
    }

    /// Whether the section belongs to a journal (kinds 1 to 5).
    #[must_use]
    pub const fn per_journal(self) -> bool {
        (self as u16) <= 5
    }
}

/// One section: its kind, journal identity, count and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Its kind.
    pub kind: SectionKind,
    /// The integrity journal identity it belongs to; 0 for none.
    pub journal: u64,
    /// Its rows or chunks.
    pub count: u64,
    /// Its body, a multiple of 8 bytes.
    pub body: Vec<u8>,
}

/// A decoded export: the header's fields and the sections, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The exporting Archive's identity.
    pub archive_id: Digest,
    /// When it was written, UTC ns; 0 not stated; never evidence.
    pub created_utc_ns: u64,
    /// The sections.
    pub sections: Vec<Section>,
}

/// Why an export is refused, in the order of the checks (design section
/// 6): the file's, then each section's in turn, then the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// The trailer does not match, or the file is shorter than a header and
    /// a trailer.
    #[error("the export's trailer does not match, or the file is truncated")]
    Trailer,
    /// Not the export magic.
    #[error("not an export: bad magic")]
    Magic,
    /// Not version 1.
    #[error("export version {0} is not supported")]
    Version(u16),
    /// A reserved field is not zero; `None` for the header's.
    #[error("a reserved field is not zero")]
    Reserved {
        /// The section, from 0, or `None` for the header.
        section: Option<u32>,
    },
    /// An unknown section kind.
    #[error("section {section} has unknown kind {kind}")]
    Kind {
        /// The section, from 0.
        section: u32,
        /// Its kind code.
        kind: u16,
    },
    /// A section version other than 1.
    #[error("section {section} has version {version}")]
    SectionVersion {
        /// The section, from 0.
        section: u32,
        /// Its version.
        version: u16,
    },
    /// A length not a multiple of 8, not `count` rows or chunks, or past
    /// the trailer.
    #[error("section {section} has a bad length")]
    Length {
        /// The section, from 0.
        section: u32,
    },
    /// The sections are not in the design's section 4 order.
    #[error("section {section} is out of order")]
    Order {
        /// The section, from 0.
        section: u32,
    },
    /// `section_count` is not the sections found.
    #[error("the header counts {declared} sections, the file holds {found}")]
    Count {
        /// The header's count.
        declared: u32,
        /// The sections read.
        found: u32,
    },
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..)?
        .first_chunk::<2>()
        .map(|b| u16::from_le_bytes(*b))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..)?
        .first_chunk::<4>()
        .map(|b| u32::from_le_bytes(*b))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..)?
        .first_chunk::<8>()
        .map(|b| u64::from_le_bytes(*b))
}

/// The bytes of a chunk (a `Frames` or `CodecSchemas` entry): its header
/// fields then its payload, padded with zero bytes to a multiple of 8.
#[must_use]
pub fn chunk(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len().saturating_add(payload.len()).saturating_add(7));
    out.extend_from_slice(header);
    out.extend_from_slice(payload);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out
}

/// A `Frames` chunk: `recording`, `start`, the bytes.
#[must_use]
pub fn frames_chunk(recording: u64, start: u64, bytes: &[u8]) -> Vec<u8> {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&recording.to_le_bytes());
    header.extend_from_slice(&start.to_le_bytes());
    header.extend_from_slice(&length.to_le_bytes());
    chunk(&header, bytes)
}

/// Encodes an export: the header, `sections` in the given order, then the
/// trailer. The section count and lengths are computed; the bodies are
/// written as given, and their padding and order are the caller's.
#[must_use]
pub fn encode(archive_id: &Digest, created_utc_ns: u64, sections: &[Section]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let count = u32::try_from(sections.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(archive_id);
    out.extend_from_slice(&created_utc_ns.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    for section in sections {
        out.extend_from_slice(&(section.kind as u16).to_le_bytes());
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&section.journal.to_le_bytes());
        out.extend_from_slice(&section.count.to_le_bytes());
        let length = u64::try_from(section.body.len()).unwrap_or(u64::MAX);
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&section.body);
    }
    let trailer: [u8; TRAILER_LENGTH] = Sha256::digest(&out).into();
    out.extend_from_slice(&trailer);
    out
}

/// Decodes an export, checking the file, each section and their order, as
/// design section 6 orders the refusals.
///
/// # Errors
///
/// The first [`ExportError`].
pub fn decode(bytes: &[u8]) -> Result<Export, ExportError> {
    let body_end = bytes
        .len()
        .checked_sub(TRAILER_LENGTH)
        .filter(|end| *end >= HEADER_LENGTH)
        .ok_or(ExportError::Trailer)?;
    let (content, trailer) = bytes.split_at(body_end);
    let digest: [u8; TRAILER_LENGTH] = Sha256::digest(content).into();
    if digest.as_slice() != trailer {
        return Err(ExportError::Trailer);
    }
    if content.get(..8) != Some(&MAGIC[..]) {
        return Err(ExportError::Magic);
    }
    let version = u16_at(content, 8).ok_or(ExportError::Trailer)?;
    if version != VERSION {
        return Err(ExportError::Version(version));
    }
    let declared = u32_at(content, 12).ok_or(ExportError::Trailer)?;
    if u16_at(content, 10) != Some(0) || u64_at(content, 56) != Some(0) {
        return Err(ExportError::Reserved { section: None });
    }
    let archive_id: Digest = content
        .get(16..48)
        .and_then(|id| id.try_into().ok())
        .ok_or(ExportError::Trailer)?;
    let created_utc_ns = u64_at(content, 48).ok_or(ExportError::Trailer)?;
    let mut sections = Vec::new();
    let mut at = HEADER_LENGTH;
    let mut order = Order::default();
    let mut index = 0u32;
    while at < content.len() {
        let length_error = ExportError::Length { section: index };
        let header = content
            .get(at..at.saturating_add(SECTION_HEADER_LENGTH))
            .ok_or(length_error)?;
        if u32_at(header, 4) != Some(0) {
            return Err(ExportError::Reserved {
                section: Some(index),
            });
        }
        let code = u16_at(header, 0).ok_or(length_error)?;
        let kind = SectionKind::from_code(code).ok_or(ExportError::Kind {
            section: index,
            kind: code,
        })?;
        let section_version = u16_at(header, 2).ok_or(length_error)?;
        if section_version != VERSION {
            return Err(ExportError::SectionVersion {
                section: index,
                version: section_version,
            });
        }
        let journal = u64_at(header, 8).ok_or(length_error)?;
        let count = u64_at(header, 16).ok_or(length_error)?;
        let length = u64_at(header, 24)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(length_error)?;
        let start = at.saturating_add(SECTION_HEADER_LENGTH);
        let body = start
            .checked_add(length)
            .and_then(|end| content.get(start..end))
            .filter(|_| length.is_multiple_of(8))
            .ok_or(length_error)?;
        if !fits(kind, count, body) {
            return Err(length_error);
        }
        if !order.accepts(kind, journal, body) {
            return Err(ExportError::Order { section: index });
        }
        sections.push(Section {
            kind,
            journal,
            count,
            body: body.to_vec(),
        });
        at = start.saturating_add(length);
        index = index.saturating_add(1);
    }
    if index != declared {
        return Err(ExportError::Count {
            declared,
            found: index,
        });
    }
    Ok(Export {
        archive_id,
        created_utc_ns,
        sections,
    })
}

/// Whether `body` is `count` rows of `kind`, or `count` well formed chunks.
fn fits(kind: SectionKind, count: u64, body: &[u8]) -> bool {
    if let Some(row) = kind.row_length() {
        let rows = u64::try_from(body.len() / row).unwrap_or(u64::MAX);
        return body.len().is_multiple_of(row)
            && rows == count
            && (kind != SectionKind::Journal || count == 1);
    }
    // A chunk: its fixed header, the payload length at `length_at`, then
    // the payload padded to 8.
    let (fixed, length_at) = match kind {
        SectionKind::Frames => (24usize, 16usize),
        _ => (16usize, 8usize),
    };
    let mut at = 0usize;
    let mut chunks = 0u64;
    while at < body.len() {
        let Some(length) = u64_at(body, at.saturating_add(length_at))
            .and_then(|length| usize::try_from(length).ok())
        else {
            return false;
        };
        let padded = length.saturating_add(7) / 8 * 8;
        let Some(next) = at.checked_add(fixed).and_then(|at| at.checked_add(padded)) else {
            return false;
        };
        if next > body.len() || (kind == SectionKind::Frames && length == 0) {
            return false;
        }
        at = next;
        chunks = chunks.saturating_add(1);
    }
    chunks == count
}

/// The design's section 4 order: groups of journal sections (each opened
/// by its `Journal`, its other kinds ascending, the Archive's journal
/// first), then each other kind at most once, ascending.
#[derive(Debug, Default)]
struct Order {
    /// The journal and the last kind of the group being read.
    group: Option<(u64, SectionKind)>,
    /// Whether a group was read.
    any_group: bool,
    /// The last non-journal kind read.
    last: Option<SectionKind>,
}

impl Order {
    fn accepts(&mut self, kind: SectionKind, journal: u64, body: &[u8]) -> bool {
        if kind.per_journal() {
            if self.last.is_some() {
                return false;
            }
            if kind == SectionKind::Journal {
                // The Archive's journal (role 1) comes first.
                let role = u16_at(body, 0);
                if !self.any_group && role != Some(1) {
                    return false;
                }
                if self.any_group && role == Some(1) {
                    return false;
                }
                self.group = Some((journal, kind));
                self.any_group = true;
                return true;
            }
            return match self.group {
                Some((open, last)) if open == journal && kind > last => {
                    self.group = Some((journal, kind));
                    true
                }
                _ => false,
            };
        }
        if journal != 0 && kind != SectionKind::TimeEvidence {
            return false;
        }
        if self.last.is_some_and(|last| kind <= last) {
            return false;
        }
        self.last = Some(kind);
        true
    }
}
