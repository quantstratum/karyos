// SPDX-License-Identifier: Apache-2.0

//! The catalog of a sealed range's copies and the immutability each one
//! has (quantstratum-docs: karyos/SPEC.md §8.4, "Immutability
//! enforcement", "Replication" and "Tiered storage"; karyos#664).
//!
//! Copies may live on storage with different capabilities, so the catalog
//! records, per copy, where it is, what state it is in and which
//! immutability enforcement applies: an immutable file attribute,
//! object-lock retention, or none where the storage does not support it.
//! Each record's digest is chained in the integrity journal as a copy
//! change ([`SealKind::Copy`]), so the copy catalog is covered by the same
//! evidence as the data, and its state is replayed in journal order.
//!
//! Immutability complements the hash chain and proves nothing on its own:
//! a copy marked immutable is still verified through its seal, and a copy
//! with no enforcement is reported as such ([`Enforcement::Unsupported`]),
//! never silently treated as protected.
//!
//! Setting an immutable attribute needs a system call outside what the
//! Archive crate may do (`unsafe` lives in `karyos-sys`), so enforcement
//! goes through [`ImmutabilityBackend`]; the backend that ships here,
//! [`NoImmutability`], reports `Unsupported`. A file attribute backend in
//! `karyos-sys` and the object-lock backend of the tiering client
//! (karyos#669) plug in behind the same trait.

use std::path::Path;

use super::journal::{IntegrityError, IntegrityJournal};
use super::ledger::Ledger;
use super::{Digest, SealKind, SealRecord};
use crate::disk::Disk;

/// The copy catalog's file name in the archive directory.
pub const COPIES_FILE: &str = "copies.kyc";

/// The encoded length of a copy record, in bytes.
pub const COPY_RECORD_LENGTH: usize = 112;

/// The copy record format version.
pub const COPY_VERSION: u16 = 1;

/// The immutability enforcement of a copy. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Enforcement {
    /// The storage cannot enforce immutability; the chain is the only
    /// evidence.
    Unsupported = 1,
    /// An immutable file attribute, until the retention ends.
    ImmutableAttribute = 2,
    /// Object-lock retention on object storage.
    ObjectLock = 3,
}

/// The state of a copy. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum CopyState {
    /// Bytes are there but were not verified against the seal: counts
    /// towards nothing.
    Unverified = 1,
    /// Verified against the seal: counts as a copy.
    Verified = 2,
    /// Removed.
    Removed = 3,
}

/// One record of the copy catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyRecord {
    /// The record's sequence: 0, then one more each time.
    pub sequence: u64,
    /// The recording.
    pub recording: u64,
    /// The start of the copied range.
    pub start: u64,
    /// Its end, exclusive.
    pub end: u64,
    /// Where the copy is: this Archive's id, a replica's, a bucket's.
    pub location: Digest,
    /// The digest of the copied range, as its seal states it.
    pub digest: Digest,
    /// Until when the copy is to be retained, in ns of UTC; 0 for none.
    pub retain_until_ns: u64,
    /// Its state.
    pub state: CopyState,
    /// Its immutability enforcement.
    pub enforcement: Enforcement,
}

/// Why a copy record could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CopyDecodeError {
    /// A version this code does not read.
    #[error("copy record version {0} is not supported")]
    Version(u16),
    /// An unknown state or enforcement.
    #[error("copy record field {field} has unknown value {value}")]
    Unknown {
        /// The field.
        field: &'static str,
        /// The value.
        value: u8,
    },
}

impl CopyRecord {
    /// The encoded record, version 1, little-endian at fixed offsets:
    /// version `u16`, state `u8`, enforcement `u8`, four reserved zero
    /// bytes, sequence, recording, start, end and retention `u64`s, the
    /// location and the digest.
    #[must_use]
    pub fn encode(&self) -> [u8; COPY_RECORD_LENGTH] {
        let mut out = [0u8; COPY_RECORD_LENGTH];
        let fields = [
            &COPY_VERSION.to_le_bytes()[..],
            &[self.state as u8, self.enforcement as u8, 0, 0, 0, 0],
            &self.sequence.to_le_bytes(),
            &self.recording.to_le_bytes(),
            &self.start.to_le_bytes(),
            &self.end.to_le_bytes(),
            &self.retain_until_ns.to_le_bytes(),
            &self.location,
            &self.digest,
        ];
        for (slot, byte) in out.iter_mut().zip(fields.into_iter().flatten()) {
            *slot = *byte;
        }
        out
    }

    /// Reads an encoded record.
    ///
    /// # Errors
    ///
    /// [`CopyDecodeError`] for an unknown version, state or enforcement.
    pub fn decode(bytes: &[u8; COPY_RECORD_LENGTH]) -> Result<Self, CopyDecodeError> {
        let u64_at = |offset: usize| {
            bytes
                .get(offset..)
                .and_then(|rest| rest.first_chunk::<8>())
                .map_or(0, |chunk| u64::from_le_bytes(*chunk))
        };
        let digest_at = |offset: usize| {
            bytes
                .get(offset..)
                .and_then(|rest| rest.first_chunk::<32>())
                .copied()
                .unwrap_or([0; 32])
        };
        let [version_low, version_high, state, enforcement, ..] = *bytes;
        let version = u16::from_le_bytes([version_low, version_high]);
        if version != COPY_VERSION {
            return Err(CopyDecodeError::Version(version));
        }
        let state = match state {
            1 => CopyState::Unverified,
            2 => CopyState::Verified,
            3 => CopyState::Removed,
            value => {
                return Err(CopyDecodeError::Unknown {
                    field: "state",
                    value,
                });
            }
        };
        let enforcement = match enforcement {
            1 => Enforcement::Unsupported,
            2 => Enforcement::ImmutableAttribute,
            3 => Enforcement::ObjectLock,
            value => {
                return Err(CopyDecodeError::Unknown {
                    field: "enforcement",
                    value,
                });
            }
        };
        Ok(Self {
            sequence: u64_at(8),
            recording: u64_at(16),
            start: u64_at(24),
            end: u64_at(32),
            retain_until_ns: u64_at(40),
            location: digest_at(48),
            digest: digest_at(80),
            state,
            enforcement,
        })
    }

    /// Whether this record is about the same copy as `other`.
    fn same_copy(&self, other: &Self) -> bool {
        (self.recording, self.start, self.end, self.location)
            == (other.recording, other.start, other.end, other.location)
    }
}

/// Makes a stored copy immutable until its retention ends, where the
/// storage can.
pub trait ImmutabilityBackend {
    /// Enforces immutability of `path` until `retain_until_ns`, returning
    /// what applies.
    ///
    /// # Errors
    ///
    /// The storage's error; a storage that cannot enforce returns
    /// `Ok(Enforcement::Unsupported)` instead.
    fn enforce(&mut self, path: &Path, retain_until_ns: u64) -> std::io::Result<Enforcement>;
}

/// The backend for storage with no immutability: it states so.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoImmutability;

impl ImmutabilityBackend for NoImmutability {
    fn enforce(&mut self, _path: &Path, _retain_until_ns: u64) -> std::io::Result<Enforcement> {
        Ok(Enforcement::Unsupported)
    }
}

/// The copy catalog of an archive directory.
#[derive(Debug)]
pub struct CopyCatalog<D: Disk> {
    ledger: Ledger<D, COPY_RECORD_LENGTH>,
    records: Vec<CopyRecord>,
}

impl<D: Disk> CopyCatalog<D> {
    /// Opens the copy catalog of `dir` by replaying, in journal order, the
    /// copy changes `journal` chains, reading each one's bytes from the
    /// ledger by its digest. A record stored before a crash or a failed
    /// journal append is not committed, so it never counts, and a retry
    /// that stored the same bytes again is applied once.
    ///
    /// # Errors
    ///
    /// As [`Ledger::open`] and [`IntegrityJournal::records`];
    /// [`IntegrityError::Unrecorded`] for a copy change the journal chains
    /// whose record the ledger does not hold or that does not match the
    /// journal's record of it.
    pub fn open(
        disk: D,
        dir: &Path,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<Self, IntegrityError> {
        let ledger = Ledger::open(disk, dir, COPIES_FILE)?;
        let stored: std::collections::BTreeMap<Digest, &[u8; COPY_RECORD_LENGTH]> = ledger
            .entries()
            .iter()
            .rev()
            .map(|bytes| (super::digest(bytes), bytes))
            .collect();
        let mut records = Vec::new();
        for change in journal.records()? {
            if change.kind != SealKind::Copy {
                continue;
            }
            let unrecorded = IntegrityError::Unrecorded {
                counter: change.counter,
            };
            let bytes = stored.get(&change.content).ok_or(unrecorded)?;
            let record = CopyRecord::decode(bytes).map_err(|_| IntegrityError::Unrecorded {
                counter: change.counter,
            })?;
            let expected = u64::try_from(records.len()).unwrap_or(u64::MAX);
            if record.recording != change.subject
                || record.sequence != change.start
                || record.sequence != expected
            {
                return Err(IntegrityError::Unrecorded {
                    counter: change.counter,
                });
            }
            records.push(record);
        }
        Ok(Self { ledger, records })
    }

    /// Every record, oldest first.
    #[must_use]
    #[inline]
    pub fn records(&self) -> &[CopyRecord] {
        &self.records
    }

    /// The sequence the next record gets.
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        u64::try_from(self.records.len()).unwrap_or(u64::MAX)
    }

    /// Records a copy's new state: the record is stored, then its digest
    /// is chained in `journal` as a copy change of its recording, and
    /// only then is it part of the catalog's state. The record's sequence
    /// is assigned here.
    ///
    /// # Errors
    ///
    /// The ledger's or the journal's error; the state is unchanged then.
    pub fn record(
        &mut self,
        mut record: CopyRecord,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<SealRecord, IntegrityError> {
        record.sequence = self.next_sequence();
        let bytes = record.encode();
        self.ledger.append(bytes)?;
        let chained = journal.record_copy_change(record.recording, record.sequence, &bytes)?;
        self.records.push(record);
        Ok(chained)
    }

    /// The latest record of every copy, in the order each copy first
    /// appeared.
    #[must_use]
    pub fn current(&self) -> Vec<CopyRecord> {
        let mut current: Vec<CopyRecord> = Vec::new();
        for record in &self.records {
            match current.iter_mut().find(|copy| copy.same_copy(record)) {
                Some(copy) => *copy = *record,
                None => current.push(*record),
            }
        }
        current
    }

    /// The copies of `recording` whose latest state is verified and that
    /// cover `[start, end)`, counted once per location.
    #[must_use]
    pub fn verified_copies(&self, recording: u64, start: u64, end: u64) -> u64 {
        let mut locations: Vec<Digest> = self
            .current()
            .into_iter()
            .filter(|copy| {
                copy.recording == recording
                    && copy.state == CopyState::Verified
                    && copy.start <= start
                    && copy.end >= end
            })
            .map(|copy| copy.location)
            .collect();
        locations.sort_unstable();
        locations.dedup();
        u64::try_from(locations.len()).unwrap_or(u64::MAX)
    }
}
