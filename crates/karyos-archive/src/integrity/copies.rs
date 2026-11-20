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

    /// Releases the immutability of `path`, as a purge does right before
    /// it deletes the file, once every retention check passed
    /// (karyos#995). Success means the file can be removed as far as this
    /// backend is concerned; a backend that enforces nothing releases
    /// nothing.
    ///
    /// # Errors
    ///
    /// The storage's error, when the enforcement is still in place.
    fn release(&mut self, path: &Path) -> std::io::Result<()> {
        let _ = path;
        Ok(())
    }
}

/// The backend for storage with no immutability: it states so.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoImmutability;

impl ImmutabilityBackend for NoImmutability {
    fn enforce(&mut self, _path: &Path, _retain_until_ns: u64) -> std::io::Result<Enforcement> {
        Ok(Enforcement::Unsupported)
    }
}

/// The backend that sets a sealed segment's immutable file attribute
/// through `karyos-sys` (Linux, `FS_IMMUTABLE_FL`; karyos#958). Where the
/// file system has no such attribute, or the process may not set it
/// (`CAP_LINUX_IMMUTABLE`), it reports [`Enforcement::Unsupported`]: the
/// catalog then records that no enforcement applies, never a protection
/// that is not there.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImmutableAttribute;

#[cfg(target_os = "linux")]
impl ImmutableAttribute {
    /// Clears the attribute of `path`, as a purge must before it removes
    /// the file, and only once every retention check has passed. Only a
    /// cleared attribute is success: a refusal is never reported as a
    /// release, so a purge never goes on with the file still immutable.
    ///
    /// # Errors
    ///
    /// The file cannot be opened or its flags changed;
    /// [`std::io::ErrorKind::PermissionDenied`] when this process may not
    /// change the attribute (`CAP_LINUX_IMMUTABLE`), and
    /// [`std::io::ErrorKind::Unsupported`] when the file system has none.
    pub fn release(&mut self, path: &Path) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};
        match karyos_sys::fs::set_immutable(path, false).map_err(Error::other)? {
            karyos_sys::fs::Immutability::Applied => Ok(()),
            karyos_sys::fs::Immutability::NotPermitted => Err(Error::new(
                ErrorKind::PermissionDenied,
                "the immutable attribute may not be cleared",
            )),
            karyos_sys::fs::Immutability::Unsupported => Err(Error::new(
                ErrorKind::Unsupported,
                "the file system has no immutable attribute",
            )),
            // An outcome a newer karyos-sys adds is not a release.
            _ => Err(Error::other(
                "an immutability outcome this version does not know",
            )),
        }
    }
}

#[cfg(target_os = "linux")]
impl ImmutabilityBackend for ImmutableAttribute {
    fn enforce(&mut self, path: &Path, _retain_until_ns: u64) -> std::io::Result<Enforcement> {
        match karyos_sys::fs::set_immutable(path, true).map_err(std::io::Error::other)? {
            karyos_sys::fs::Immutability::Applied => Ok(Enforcement::ImmutableAttribute),
            // Anything else, an outcome a newer karyos-sys adds included,
            // records no enforcement: never a protection that is not there.
            _ => Ok(Enforcement::Unsupported),
        }
    }

    /// The inherent [`ImmutableAttribute::release`], except that a file
    /// system with no attribute has nothing to release: its segments were
    /// recorded [`Enforcement::Unsupported`], and a purge goes on.
    fn release(&mut self, path: &Path) -> std::io::Result<()> {
        match Self::release(self, path) {
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => Ok(()),
            other => other,
        }
    }
}

/// The copy catalog of an archive directory.
#[derive(Debug)]
pub struct CopyCatalog<D: Disk> {
    ledger: Ledger<D, COPY_RECORD_LENGTH>,
    /// The journal handle the catalog was replayed from: the only one it
    /// records through.
    journal: u64,
    records: Vec<CopyRecord>,
    /// Set when a change reached the ledger but its journal append failed:
    /// whether the journal holds it is unknown until reopened, so the live
    /// state answers nothing.
    poisoned: bool,
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
    /// [`IntegrityError::Poisoned`] for a journal handle an earlier append
    /// poisoned and [`IntegrityError::StaleJournal`] for one behind the
    /// file, before anything is read; as [`Ledger::open`] and
    /// [`IntegrityJournal::records`];
    /// [`IntegrityError::Unrecorded`] for a copy change the journal chains
    /// whose record the ledger does not hold or that does not match the
    /// journal's record of it.
    pub fn open(
        disk: D,
        dir: &Path,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<Self, IntegrityError> {
        // A poisoned handle reads only the records it knows of: a change
        // whose sync failed may still be on disk. Reopen the journal first.
        if journal.is_poisoned() {
            return Err(IntegrityError::Poisoned);
        }
        // A view behind the file would replay stale copy state.
        if !journal.is_current()? {
            return Err(IntegrityError::StaleJournal);
        }
        // Only the journal of this archive directory: another journal's
        // copy changes are not this catalog's.
        if journal.dir() != dir {
            return Err(IntegrityError::ForeignLedger);
        }
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
        Ok(Self {
            ledger,
            journal: journal.handle(),
            records,
            poisoned: false,
        })
    }

    /// Whether a change's journal append failed since the catalog was
    /// opened: its live state is uncertain until it is reopened.
    #[must_use]
    #[inline]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
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
    /// [`IntegrityError::ForeignLedger`] for a journal handle other than
    /// the one the catalog was replayed from;
    /// [`IntegrityError::StaleCatalog`] when another handle recorded a
    /// change since this one was opened, [`IntegrityError::Poisoned`] for
    /// a poisoned journal and [`IntegrityError::StaleJournal`] for one
    /// behind the file, with nothing written; otherwise the ledger's
    /// or the journal's error. The state is unchanged on an error.
    pub fn record(
        &mut self,
        mut record: CopyRecord,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<SealRecord, IntegrityError> {
        record.sequence = self.next_sequence();
        if self.poisoned {
            return Err(IntegrityError::Poisoned);
        }
        // Bound to the journal handle it replayed: any other journal,
        // whatever its path or storage, would chain this change while this
        // catalog's own journal never commits it.
        if journal.handle() != self.journal || journal.dir() != self.ledger.dir() {
            return Err(IntegrityError::ForeignLedger);
        }
        // Compare and swap: only a catalog that holds every change the
        // journal chains may record the next one.
        if journal.is_poisoned() {
            return Err(IntegrityError::Poisoned);
        }
        if !journal.is_current()? {
            return Err(IntegrityError::StaleJournal);
        }
        if journal.copy_changes() != record.sequence {
            return Err(IntegrityError::StaleCatalog);
        }
        let bytes = record.encode();
        self.ledger.append(bytes)?;
        let chained = match journal.record_copy_change(record.recording, record.sequence, &bytes) {
            Ok(chained) => chained,
            Err(error) => {
                // The record may or may not be on the journal: the live
                // counts are uncertain until the catalog is reopened.
                self.poisoned = true;
                return Err(error);
            }
        };
        self.records.push(record);
        Ok(chained)
    }

    /// Enforces immutability on the closed, sealed segment file `path`
    /// through `backend` and records `record`, the segment's copy, with
    /// the enforcement that applies (karyos#995): never one that is not
    /// there. A backend error records nothing.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Io`] from the backend; then as
    /// [`CopyCatalog::record`].
    pub fn record_enforced(
        &mut self,
        mut record: CopyRecord,
        path: &Path,
        backend: &mut dyn ImmutabilityBackend,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<SealRecord, IntegrityError> {
        record.enforcement = backend.enforce(path, record.retain_until_ns)?;
        self.record(record, journal)
    }

    /// The latest record of every copy, in the order each copy first
    /// appeared.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Poisoned`] after a change whose journal append
    /// failed: the current state is uncertain until the catalog is
    /// reopened.
    pub fn current(&self) -> Result<Vec<CopyRecord>, IntegrityError> {
        if self.poisoned {
            return Err(IntegrityError::Poisoned);
        }
        Ok(self.latest())
    }

    /// The latest record of every copy, poisoned or not.
    fn latest(&self) -> Vec<CopyRecord> {
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
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Poisoned`] after a change whose journal append
    /// failed: the counts are uncertain until the catalog is reopened, and
    /// no retention decision may rest on them.
    pub fn verified_copies(
        &self,
        recording: u64,
        start: u64,
        end: u64,
    ) -> Result<u64, IntegrityError> {
        if self.poisoned {
            return Err(IntegrityError::Poisoned);
        }
        let mut locations: Vec<Digest> = self
            .latest()
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
        Ok(u64::try_from(locations.len()).unwrap_or(u64::MAX))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod immutable_tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// The backend reports the attribute it set, or that none applies;
    /// an applied attribute holds until released.
    #[test]
    fn the_attribute_backend_reports_what_applies() {
        let dir = std::env::temp_dir().join(format!("karyos-copies-imm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealed.seg");
        std::fs::write(&path, b"sealed").unwrap();
        let mut backend = ImmutableAttribute;
        match backend.enforce(&path, u64::MAX).unwrap() {
            Enforcement::ImmutableAttribute => {
                assert!(std::fs::remove_file(&path).is_err());
                backend.release(&path).unwrap();
                std::fs::remove_file(&path).unwrap();
            }
            enforcement => assert_eq!(enforcement, Enforcement::Unsupported),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// karyos#958 review P2: a release succeeds only when the attribute
    /// was cleared; a refusal (no permission, or no such attribute) is a
    /// typed error, never a release.
    #[test]
    fn a_release_that_clears_nothing_is_an_error() {
        let dir = std::env::temp_dir().join(format!("karyos-copies-rel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealed.seg");
        std::fs::write(&path, b"sealed").unwrap();
        let direct = karyos_sys::fs::set_immutable(&path, false).unwrap();
        let released = ImmutableAttribute.release(&path);
        match direct {
            karyos_sys::fs::Immutability::Applied => released.unwrap(),
            karyos_sys::fs::Immutability::NotPermitted => assert_eq!(
                released.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            ),
            karyos_sys::fs::Immutability::Unsupported => assert_eq!(
                released.unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            ),
            _ => assert!(released.is_err()),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
