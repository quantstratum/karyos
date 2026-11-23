// SPDX-License-Identifier: Apache-2.0

//! The replica side of recording replication: a range counts as a copy
//! only once its stored bytes verified against its source seal
//! (quantstratum-docs: karyos/SPEC.md §8.4, "Replication"; ADR-0102
//! decision 5; karyos#669, #1113).
//!
//! Copying bytes is not a copy. Bytes that arrive change no copy record;
//! when the source seal arrives, [`Replica::verify`] checks the stored
//! bytes against it through [`verify_range`] before anything is recorded,
//! and only a match is recorded [`CopyState::Verified`], once. A mismatch
//! is reported and records nothing: it neither counts towards
//! `min_copies` (karyos#667) nor downgrades a copy verified before. Only
//! the replica's own check of its stored bytes, [`Replica::invalidate`],
//! does that.
//!
//! The transport, Karyos streams from a source Archive, is not here: this
//! module is what a replica does with what the transport delivers.

use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::{IntegrityError, IntegrityJournal};
use super::{Digest, Inconsistency, SealRecord, verify_range};
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
    /// The range is inverted.
    #[error("range [{start}, {end}) ends before it starts")]
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

/// The outcome of checking stored bytes against their source seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// The bytes match the seal: the range now counts as a copy, recorded
    /// by this catalog change.
    Counted(SealRecord),
    /// The bytes match the seal and the range already counted here: no
    /// catalog change.
    AlreadyCounted,
    /// The bytes differ from the seal: nothing was recorded, and the range
    /// keeps the state it had.
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

    /// Checks the replica's stored `bytes` of a range against its source
    /// `seal` before anything is recorded. A match for a range not yet
    /// counted here is recorded [`CopyState::Verified`]; a match for one
    /// already counted changes nothing ([`Verdict::AlreadyCounted`]), so
    /// a replayed seal is idempotent; a mismatch records nothing and is
    /// returned as [`Verdict::Corrupt`].
    ///
    /// # Errors
    ///
    /// [`ReplicationError::NotARange`] for a seal of no range, or the
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
        if let Err(inconsistency) = verify_range(seal, bytes) {
            return Ok(Verdict::Corrupt(inconsistency));
        }
        let counted = copies.current()?.into_iter().any(|copy| {
            copy.location == self.location
                && copy.recording == seal.subject
                && copy.start == seal.start
                && copy.end == seal.end
                && copy.digest == seal.content
                && copy.state == CopyState::Verified
        });
        if counted {
            return Ok(Verdict::AlreadyCounted);
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

    /// Downgrades every copy here of `recording` that is verified and
    /// overlaps `[start, end)` to [`CopyState::Unverified`]. Only for the
    /// replica's own check of its stored bytes failing (a scrub, a verify
    /// of the integrity journal), never for what the source sends
    /// (ADR-0102 decision 5). Returns how many copies stopped counting.
    ///
    /// # Errors
    ///
    /// [`ReplicationError::InvertedRange`], or the catalog's error.
    pub fn invalidate<D: Disk>(
        &self,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        recording: u64,
        start: u64,
        end: u64,
    ) -> Result<u64, ReplicationError> {
        if end < start {
            return Err(ReplicationError::InvertedRange { start, end });
        }
        let counted: Vec<CopyRecord> = copies
            .current()?
            .into_iter()
            .filter(|copy| {
                copy.location == self.location
                    && copy.recording == recording
                    && copy.state == CopyState::Verified
                    && copy.start < end
                    && start < copy.end
            })
            .collect();
        let mut downgraded = 0u64;
        for mut copy in counted {
            copy.state = CopyState::Unverified;
            copies.record(copy, journal)?;
            downgraded = downgraded.saturating_add(1);
        }
        Ok(downgraded)
    }

    /// The replication lag of `recording` against the source, whose
    /// recording starts at `source_start` and is sealed to
    /// `source_sealed_end`: only coverage contiguous from the source's
    /// start counts, so a missing prefix shows.
    ///
    /// # Errors
    ///
    /// The copy catalog's error.
    pub fn lag<D: Disk>(
        &self,
        copies: &CopyCatalog<D>,
        recording: u64,
        source_start: u64,
        source_sealed_end: u64,
    ) -> Result<ReplicationLag, IntegrityError> {
        let mut verified: Vec<(u64, u64)> = copies
            .current()?
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
        Ok(ReplicationLag {
            source_sealed_end,
            verified_end,
            behind: source_sealed_end.saturating_sub(verified_end),
        })
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
