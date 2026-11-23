// SPDX-License-Identifier: Apache-2.0

//! Sealing and the tamper-evidence hash chain (quantstratum-docs:
//! karyos/SPEC.md §8.4, "Sealing and tamper evidence"; ADR-0051 item 2;
//! karyos#662, plan issue 046).
//!
//! When a segment is closed, and at a bounded `seal_interval` for a
//! segment still open, the Archive computes the SHA-256 digest of the
//! sealed range and appends a [`SealRecord`] to the append-only
//! integrity journal ([`journal`]). Each record carries a monotonic
//! counter and the digest of its predecessor, so the journal is a hash
//! chain: an altered byte in a sealed range, a removed record, a
//! reordered record and a gap in the counter are each detected and named
//! by an [`Inconsistency`].
//!
//! The chain covers more than payload bytes: catalog changes, policy
//! versions, key registry appends and purges are records of their own
//! kind ([`SealKind`]), so the catalog or a policy cannot be rewritten
//! without breaking the chain. A Cluster log recording is sealed only up
//! to the position of its commit index ([`journal::IntegrityJournal::seal_cluster_log`]),
//! because Raft may still truncate an uncommitted suffix.
//!
//! # CRC-32C is corruption detection; the seal is integrity
//!
//! The CRC-32C of [`crate::crc32c`] and of the segment entries stays where
//! it is and is not replaced: it detects accidental corruption of a frame
//! or a record, and anyone who changes the bytes can recompute it. The
//! seal digest, chained and later signed and anchored (karyos#663,
//! karyos#664), is the integrity evidence. Each seal record also carries a
//! CRC-32C of its own bytes, used only to tell a torn tail write from a
//! complete record during recovery; it never stands in for the chain.
//!
//! # Referenced payloads
//!
//! A recording group's [`crate::group::record::Payload::Reference`] names
//! a recording and a length. Decision recorded for karyos#662: once the
//! range holding the referenced payload is sealed, its integrity rests on
//! the seal of that range (verified through [`verify_range`]); until then
//! it rests only on the segment entry's CRC-32C, which is corruption
//! detection, and the verifier reports such a range as `unsealed`.
//!
//! # Journals as recordings
//!
//! Journals the Archive records as recordings (the operations journal, a
//! sequencer's admission journal) are sealed through the same calls as
//! any other recording ([`journal::IntegrityJournal::seal_segment`] and the
//! [`sealer::Sealer`] schedule), keyed by their recording id; nothing in
//! the chain distinguishes them, which is the point.

pub mod anchor;
pub mod copies;
pub mod damage;
pub mod export;
pub mod journal;
pub mod ledger;
pub mod replication;
pub mod retention;
pub mod sealer;
pub mod signing;
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_key;
pub mod tiering;
pub mod time;
pub mod time_evidence;
pub mod time_producer;
pub mod trust;
pub mod verify;

#[cfg(test)]
mod anchor_tests;
#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod replication_tests;
#[cfg(test)]
mod retention_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod trust_tests;
#[cfg(test)]
mod verify_tests;

use sha2::{Digest as _, Sha256};

use crate::crc32c::crc32c;

/// A SHA-256 digest.
pub type Digest = [u8; DIGEST_LENGTH];

/// The length of a SHA-256 digest, in bytes.
pub const DIGEST_LENGTH: usize = 32;

/// The seal record format this code writes and reads.
pub const SEAL_RECORD_VERSION: u16 = 1;

/// The encoded length of a seal record, in bytes.
pub const SEAL_RECORD_LENGTH: usize = 112;

/// The length of a seal record's bytes covered by its CRC-32C and its
/// record digest: everything before the CRC.
const SEALED_PREFIX_LENGTH: usize = 104;

/// The domain tag prefixed to a seal record's bytes before hashing, so a
/// record digest can never be confused with the digest of payload bytes
/// or of another structure.
const RECORD_DOMAIN: &[u8] = b"karyos/archive/integrity/seal-record/v1\0";

/// The previous digest of the first record of a chain.
pub const GENESIS: Digest = [0; DIGEST_LENGTH];

/// What a seal record covers. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum SealKind {
    /// A range of a segment still open, sealed at `seal_interval`.
    OpenSegment = 1,
    /// The last range of a segment, sealed when it closed.
    ClosedSegment = 2,
    /// A range of a Cluster log recording at or below its commit index.
    ClusterLog = 3,
    /// A catalog change: `subject` is the recording, `start` the catalog
    /// generation, the digest that of the change's canonical bytes.
    Catalog = 4,
    /// A retention policy version: `subject` is the policy, `start` its
    /// version, the digest that of its canonical bytes.
    Policy = 5,
    /// A key registry append: `subject` is the key id's first eight bytes,
    /// `start` the registry sequence, the digest that of the registry
    /// record's canonical bytes.
    KeyRegistry = 6,
    /// A purge: `subject` is the recording, `[start, end)` the purged
    /// range, the digest that of the purged segment as sealed.
    Purge = 7,
    /// A change of a copy's state in the copy catalog: `subject` is the
    /// recording, `start` and `end` the copy record's sequence, the digest
    /// that of the copy record's canonical bytes.
    Copy = 8,
}

impl SealKind {
    /// The kind of an on-disk value.
    #[must_use]
    #[inline]
    pub const fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::OpenSegment,
            2 => Self::ClosedSegment,
            3 => Self::ClusterLog,
            4 => Self::Catalog,
            5 => Self::Policy,
            6 => Self::KeyRegistry,
            7 => Self::Purge,
            8 => Self::Copy,
            _ => return None,
        })
    }

    /// Whether the record seals a range of recorded bytes, which must
    /// follow the recording's previous sealed range without a gap.
    #[must_use]
    #[inline]
    pub const fn is_range(self) -> bool {
        matches!(
            self,
            Self::OpenSegment | Self::ClosedSegment | Self::ClusterLog
        )
    }
}

/// One record of the integrity journal, version 1.
///
/// Layout, little-endian at fixed offsets: version `u16` at 0, kind
/// `u16` at 2, reserved `u32` (zero) at 4, counter `u64` at 8, subject
/// `u64` at 16, start `u64` at 24, end `u64` at 32, content digest at 40,
/// previous record digest at 72, CRC-32C of bytes 0 to 104 at 104,
/// reserved `u32` (zero) at 108.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealRecord {
    /// The kind.
    pub kind: SealKind,
    /// The position in the chain: 0 for the first record, then one more
    /// for each record.
    pub counter: u64,
    /// The recording, policy or key the record is about.
    pub subject: u64,
    /// The start of the sealed range, or a version or generation.
    pub start: u64,
    /// The end of the sealed range, exclusive; equal to `start` for a
    /// record that seals no range.
    pub end: u64,
    /// The SHA-256 digest of what the record covers.
    pub content: Digest,
    /// The record digest of the previous record, or [`GENESIS`].
    pub previous: Digest,
}

/// Why a seal record's bytes could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Fewer bytes than a record.
    #[error("a seal record needs {SEAL_RECORD_LENGTH} bytes, got {length}")]
    Short {
        /// The bytes available.
        length: usize,
    },
    /// The record's CRC-32C does not match: a torn or corrupted record.
    #[error("seal record crc {stored:#010x}, computed {computed:#010x}")]
    Crc {
        /// The stored CRC.
        stored: u32,
        /// The CRC of the bytes.
        computed: u32,
    },
    /// A version this code does not read.
    #[error("seal record version {version} is not supported")]
    Version {
        /// The version.
        version: u16,
    },
    /// An unknown kind.
    #[error("seal record kind {kind} is unknown")]
    Kind {
        /// The kind.
        kind: u16,
    },
    /// A reserved field is not zero.
    #[error("a seal record's reserved field is not zero")]
    Reserved,
}

/// A named inconsistency of the chain or of a sealed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Inconsistency {
    /// The record at `index` cannot be read.
    #[error("seal record at index {index} is malformed: {error}")]
    Malformed {
        /// The record's index in the journal.
        index: u64,
        /// Why.
        error: DecodeError,
    },
    /// The counter does not follow its predecessor: a record was removed
    /// or reordered.
    #[error("seal counter {found} where {expected} was expected")]
    CounterGap {
        /// The counter that should come next.
        expected: u64,
        /// The counter found.
        found: u64,
    },
    /// The record's previous digest is not its predecessor's digest: a
    /// record was removed, reordered or rewritten.
    #[error("seal record {counter} does not chain to its predecessor")]
    BrokenLink {
        /// The record's counter.
        counter: u64,
    },
    /// The sealed bytes no longer match the record's digest.
    #[error("the range sealed by record {counter} does not match its digest")]
    DigestMismatch {
        /// The record's counter.
        counter: u64,
    },
    /// The range does not start where the recording's previous sealed
    /// range ended.
    #[error(
        "seal record {counter} starts recording {subject} at {found}, its sealed range ends at {expected}"
    )]
    RangeGap {
        /// The record's counter.
        counter: u64,
        /// The recording.
        subject: u64,
        /// The end of the previous sealed range.
        expected: u64,
        /// The record's start.
        found: u64,
    },
    /// The range ends before it starts.
    #[error("seal record {counter} has an inverted range")]
    InvertedRange {
        /// The record's counter.
        counter: u64,
    },
}

/// The SHA-256 digest of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

/// Writes `value` into the next `N` bytes of `out`.
fn put<const N: usize>(out: &mut [u8], value: [u8; N]) -> Option<&mut [u8]> {
    let (head, rest) = out.split_first_chunk_mut::<N>()?;
    *head = value;
    Some(rest)
}

/// Reads the next `N` bytes of `bytes`.
fn take<const N: usize>(bytes: &[u8]) -> Option<([u8; N], &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<N>()?;
    Some((*head, rest))
}

impl SealRecord {
    /// The record's bytes before the CRC.
    fn prefix(&self) -> [u8; SEALED_PREFIX_LENGTH] {
        let mut out = [0u8; SEALED_PREFIX_LENGTH];
        // The fields fill the prefix exactly, as the compile-time check
        // below pins, so no step can fall short.
        let _ = Some(out.as_mut_slice())
            .and_then(|rest| put(rest, SEAL_RECORD_VERSION.to_le_bytes()))
            .and_then(|rest| put(rest, (self.kind as u16).to_le_bytes()))
            .and_then(|rest| put(rest, 0u32.to_le_bytes()))
            .and_then(|rest| put(rest, self.counter.to_le_bytes()))
            .and_then(|rest| put(rest, self.subject.to_le_bytes()))
            .and_then(|rest| put(rest, self.start.to_le_bytes()))
            .and_then(|rest| put(rest, self.end.to_le_bytes()))
            .and_then(|rest| put(rest, self.content))
            .and_then(|rest| put(rest, self.previous));
        out
    }

    /// The encoded record.
    #[must_use]
    pub fn encode(&self) -> [u8; SEAL_RECORD_LENGTH] {
        let prefix = self.prefix();
        let mut out = [0u8; SEAL_RECORD_LENGTH];
        let _ = Some(out.as_mut_slice())
            .and_then(|rest| put(rest, prefix))
            .and_then(|rest| put(rest, crc32c(&prefix).to_le_bytes()))
            .and_then(|rest| put(rest, 0u32.to_le_bytes()));
        out
    }

    /// The record digest, which the next record carries as `previous`:
    /// SHA-256 over a domain tag and the record's bytes before the CRC.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(RECORD_DOMAIN);
        hasher.update(self.prefix());
        hasher.finalize().into()
    }

    /// Reads a record from the first [`SEAL_RECORD_LENGTH`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for short bytes, a CRC mismatch, an unknown version
    /// or kind, or a reserved field that is not zero.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let short = DecodeError::Short {
            length: bytes.len(),
        };
        let (prefix, rest) = take::<SEALED_PREFIX_LENGTH>(bytes).ok_or(short)?;
        let (crc, rest) = take::<4>(rest).ok_or(short)?;
        let (tail, _) = take::<4>(rest).ok_or(short)?;
        let stored = u32::from_le_bytes(crc);
        let computed = crc32c(&prefix);
        if stored != computed {
            return Err(DecodeError::Crc { stored, computed });
        }
        let fields = || -> Option<_> {
            let (version, rest) = take::<2>(&prefix)?;
            let (kind, rest) = take::<2>(rest)?;
            let (reserved, rest) = take::<4>(rest)?;
            let (counter, rest) = take::<8>(rest)?;
            let (subject, rest) = take::<8>(rest)?;
            let (start, rest) = take::<8>(rest)?;
            let (end, rest) = take::<8>(rest)?;
            let (content, rest) = take::<DIGEST_LENGTH>(rest)?;
            let (previous, _) = take::<DIGEST_LENGTH>(rest)?;
            Some((
                u16::from_le_bytes(version),
                u16::from_le_bytes(kind),
                u32::from_le_bytes(reserved),
                u64::from_le_bytes(counter),
                u64::from_le_bytes(subject),
                u64::from_le_bytes(start),
                u64::from_le_bytes(end),
                content,
                previous,
            ))
        };
        let (version, kind, reserved, counter, subject, start, end, content, previous) =
            fields().ok_or(short)?;
        if version != SEAL_RECORD_VERSION {
            return Err(DecodeError::Version { version });
        }
        if reserved != 0 || u32::from_le_bytes(tail) != 0 {
            return Err(DecodeError::Reserved);
        }
        let kind = SealKind::from_u16(kind).ok_or(DecodeError::Kind { kind })?;
        Ok(Self {
            kind,
            counter,
            subject,
            start,
            end,
            content,
            previous,
        })
    }
}

const _: () = {
    // version, kind, reserved, counter, subject, start, end, two digests.
    let fields = 2 + 2 + 4 + 8 + 8 + 8 + 8 + DIGEST_LENGTH + DIGEST_LENGTH;
    assert!(fields == SEALED_PREFIX_LENGTH);
    assert!(SEALED_PREFIX_LENGTH + 4 + 4 == SEAL_RECORD_LENGTH);
};

/// Walks a chain record by record, checking counters, links and the
/// contiguity of each recording's sealed ranges.
#[derive(Debug, Clone, Default)]
pub struct ChainCheck {
    next_counter: u64,
    head: Option<Digest>,
    sealed_ends: std::collections::BTreeMap<u64, u64>,
    /// Where each recording's first sealed range starts: its ranges are
    /// contiguous, so they cover `[start, end)` whole.
    sealed_starts: std::collections::BTreeMap<u64, u64>,
}

impl ChainCheck {
    /// A check of a chain from its first record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The counter the next record must carry.
    #[must_use]
    #[inline]
    pub const fn next_counter(&self) -> u64 {
        self.next_counter
    }

    /// The record digest of the last record accepted, or [`GENESIS`].
    #[must_use]
    #[inline]
    pub fn head(&self) -> Digest {
        self.head.unwrap_or(GENESIS)
    }

    /// Where the sealed ranges of `recording` end, if any is sealed.
    #[must_use]
    pub fn sealed_end(&self, recording: u64) -> Option<u64> {
        self.sealed_ends.get(&recording).copied()
    }

    /// The range `[start, end)` the sealed ranges of `recording` cover
    /// whole, if any is sealed (karyos#1128).
    #[must_use]
    pub fn sealed_range(&self, recording: u64) -> Option<(u64, u64)> {
        let start = self.sealed_starts.get(&recording).copied()?;
        let end = self.sealed_ends.get(&recording).copied()?;
        Some((start, end))
    }

    /// Accepts `record` as the next record of the chain.
    ///
    /// # Errors
    ///
    /// The [`Inconsistency`] the record shows: a counter gap, a broken
    /// link, an inverted range or a range that does not follow the
    /// recording's previous one. Nothing is accepted on an error.
    pub fn accept(&mut self, record: &SealRecord) -> Result<(), Inconsistency> {
        if record.counter != self.next_counter {
            return Err(Inconsistency::CounterGap {
                expected: self.next_counter,
                found: record.counter,
            });
        }
        if record.previous != self.head() {
            return Err(Inconsistency::BrokenLink {
                counter: record.counter,
            });
        }
        if record.end < record.start {
            return Err(Inconsistency::InvertedRange {
                counter: record.counter,
            });
        }
        if record.kind.is_range()
            && let Some(&expected) = self.sealed_ends.get(&record.subject)
            && expected != record.start
        {
            return Err(Inconsistency::RangeGap {
                counter: record.counter,
                subject: record.subject,
                expected,
                found: record.start,
            });
        }
        let next = record
            .counter
            .checked_add(1)
            .ok_or(Inconsistency::CounterGap {
                expected: self.next_counter,
                found: record.counter,
            })?;
        if record.kind.is_range() {
            self.sealed_ends.insert(record.subject, record.end);
            let _ = self
                .sealed_starts
                .entry(record.subject)
                .or_insert(record.start);
        }
        self.next_counter = next;
        self.head = Some(record.digest());
        Ok(())
    }
}

/// Checks a whole chain, from its first record.
///
/// # Errors
///
/// The first [`Inconsistency`].
pub fn verify_chain<'a>(
    records: impl IntoIterator<Item = &'a SealRecord>,
) -> Result<ChainCheck, Inconsistency> {
    let mut check = ChainCheck::new();
    for record in records {
        check.accept(record)?;
    }
    Ok(check)
}

/// Checks that `bytes` are still the range `record` sealed.
///
/// # Errors
///
/// [`Inconsistency::DigestMismatch`] when their length or digest differs.
pub fn verify_range(record: &SealRecord, bytes: &[u8]) -> Result<(), Inconsistency> {
    let mismatch = Inconsistency::DigestMismatch {
        counter: record.counter,
    };
    let length = record.end.checked_sub(record.start).ok_or(mismatch)?;
    if u64::try_from(bytes.len()).ok() != Some(length) || digest(bytes) != record.content {
        return Err(mismatch);
    }
    Ok(())
}
