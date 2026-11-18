// SPDX-License-Identifier: Apache-2.0

//! The replica side of recording replication: what arrives is stored as
//! unverified, and a range counts as a copy only once it verified against
//! its source seal (quantstratum-docs: karyos/SPEC.md §8.4, "Replication";
//! karyos#669).
//!
//! Copying bytes is not a copy. A range that arrives before its seal is
//! recorded [`CopyState::Unverified`] and counts towards nothing; when the
//! source seal arrives, [`Replica::verify`] checks the stored bytes against
//! it through [`verify_range`] and only a match is recorded
//! [`CopyState::Verified`]. A mismatch is reported and recorded nowhere as
//! verified, so `min_copies` (karyos#667) never counts a corrupt copy.
//!
//! The transport, Karyos streams from a source Archive, is not here: this
//! module is what a replica does with what the transport delivers.

use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::{IntegrityError, IntegrityJournal};
use super::{Digest, GENESIS, Inconsistency, SealRecord, verify_range};
use crate::disk::Disk;

/// Why a replica could not take a range.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplicationError {
    /// The record seals no range of recorded bytes.
    #[error("seal record {counter} seals no range of recorded bytes")]
    NotARange {
        /// The record's counter.
        counter: u64,
    },
    /// The replica stored no arrival for the sealed range.
    #[error("no arrival of recording {recording} covers [{start}, {end})")]
    NotArrived {
        /// The recording.
        recording: u64,
        /// The sealed range's start.
        start: u64,
        /// Its end, exclusive.
        end: u64,
    },
    /// The arrival's range is inverted.
    #[error("arrival [{start}, {end}) ends before it starts")]
    InvertedRange {
        /// The start.
        start: u64,
        /// The end.
        end: u64,
    },
    /// The copy catalog or the integrity journal failed.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
}

/// The outcome of checking an arrival against its source seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// The bytes match the seal: the range now counts as a copy, recorded
    /// by this catalog change.
    Counted(SealRecord),
    /// The bytes differ from the seal: nothing counts.
    Corrupt(Inconsistency),
}

/// How far a replica is behind its source for one recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationLag {
    /// The end of the source's sealed ranges.
    pub source_sealed_end: u64,
    /// The end of the ranges this replica verified, contiguously from the
    /// source recording's start.
    pub verified_end: u64,
    /// The bytes sealed at the source but not yet verified here.
    pub behind: u64,
}

/// A replica Archive's view of what it holds of each recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replica {
    location: Digest,
    retain_until_ns: u64,
    enforcement: Enforcement,
}

impl Replica {
    /// A replica whose copies are catalogued at `location`, retained until
    /// `retain_until_ns` under `enforcement`.
    #[must_use]
    #[inline]
    pub const fn new(location: Digest, retain_until_ns: u64, enforcement: Enforcement) -> Self {
        Self {
            location,
            retain_until_ns,
            enforcement,
        }
    }

    /// Where this replica's copies are catalogued.
    #[must_use]
    #[inline]
    pub const fn location(&self) -> Digest {
        self.location
    }

    /// Records that `[start, end)` of `recording` arrived, before its seal:
    /// the copy is [`CopyState::Unverified`] and counts towards nothing.
    ///
    /// # Errors
    ///
    /// [`ReplicationError::InvertedRange`], or the catalog's error.
    pub fn arrived<D: Disk>(
        &self,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        recording: u64,
        start: u64,
        end: u64,
    ) -> Result<SealRecord, ReplicationError> {
        if end < start {
            return Err(ReplicationError::InvertedRange { start, end });
        }
        Ok(copies.record(
            self.record(recording, start, end, GENESIS, CopyState::Unverified),
            journal,
        )?)
    }

    /// Checks the stored `bytes` of a range against its source `seal`.
    /// Only a match is recorded [`CopyState::Verified`]; a mismatch leaves
    /// the arrival unverified and is returned as [`Verdict::Corrupt`].
    ///
    /// # Errors
    ///
    /// [`ReplicationError::NotARange`] for a seal of no range,
    /// [`ReplicationError::NotArrived`] when no arrival covers it, or the
    /// catalog's error.
    pub fn verify<D: Disk>(
        &self,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        seal: &SealRecord,
        bytes: &[u8],
    ) -> Result<Verdict, ReplicationError> {
        if !seal.kind.is_range() {
            return Err(ReplicationError::NotARange {
                counter: seal.counter,
            });
        }
        let arrived = copies.current().into_iter().any(|copy| {
            copy.location == self.location
                && copy.recording == seal.subject
                && copy.start <= seal.start
                && copy.end >= seal.end
                && copy.state != CopyState::Removed
        });
        if !arrived {
            return Err(ReplicationError::NotArrived {
                recording: seal.subject,
                start: seal.start,
                end: seal.end,
            });
        }
        if let Err(inconsistency) = verify_range(seal, bytes) {
            // A copy counted before is no longer one: every verified copy
            // here overlapping the range stops counting.
            let counted: Vec<CopyRecord> = copies
                .current()
                .into_iter()
                .filter(|copy| {
                    copy.location == self.location
                        && copy.recording == seal.subject
                        && copy.state == CopyState::Verified
                        && copy.start < seal.end
                        && seal.start < copy.end
                })
                .collect();
            for mut copy in counted {
                copy.state = CopyState::Unverified;
                copies.record(copy, journal)?;
            }
            return Ok(Verdict::Corrupt(inconsistency));
        }
        let record = self.record(
            seal.subject,
            seal.start,
            seal.end,
            seal.content,
            CopyState::Verified,
        );
        Ok(Verdict::Counted(copies.record(record, journal)?))
    }

    /// The replication lag of `recording` against the source, whose
    /// recording starts at `source_start` and is sealed to
    /// `source_sealed_end`: only coverage contiguous from the source's
    /// start counts, so a missing prefix shows.
    #[must_use]
    pub fn lag<D: Disk>(
        &self,
        copies: &CopyCatalog<D>,
        recording: u64,
        source_start: u64,
        source_sealed_end: u64,
    ) -> ReplicationLag {
        let mut verified: Vec<(u64, u64)> = copies
            .current()
            .into_iter()
            .filter(|copy| {
                copy.location == self.location
                    && copy.recording == recording
                    && copy.state == CopyState::Verified
            })
            .map(|copy| (copy.start, copy.end))
            .collect();
        verified.sort_unstable();
        let mut verified_end = source_start;
        for (start, end) in verified {
            if start > verified_end {
                break;
            }
            verified_end = verified_end.max(end);
        }
        ReplicationLag {
            source_sealed_end,
            verified_end,
            behind: source_sealed_end.saturating_sub(verified_end),
        }
    }

    const fn record(
        &self,
        recording: u64,
        start: u64,
        end: u64,
        digest: Digest,
        state: CopyState,
    ) -> CopyRecord {
        CopyRecord {
            sequence: 0,
            recording,
            start,
            end,
            location: self.location,
            digest,
            retain_until_ns: self.retain_until_ns,
            state,
            enforcement: self.enforcement,
        }
    }
}
