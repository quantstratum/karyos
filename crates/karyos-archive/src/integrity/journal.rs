// SPDX-License-Identifier: Apache-2.0

//! The integrity journal on disk: one append-only file of fixed-length
//! [`SealRecord`]s in the archive directory (SPEC.md §8.4, "Sealing and
//! tamper evidence"; karyos#662).
//!
//! An append writes one record at the end of the file and syncs it; a
//! record is reported appended only after the sync. Opening the journal
//! recovers it: a torn tail (a partial record, or a last record whose
//! CRC-32C does not match because its write was cut short) is cut off,
//! and every whole record before it must chain, or opening fails with the
//! [`Inconsistency`] found. A torn tail is what a crash while sealing
//! leaves; anything else is evidence of tampering or damage and is never
//! repaired silently.

use std::io;
use std::path::{Path, PathBuf};

use super::{
    ChainCheck, DecodeError, Digest, Inconsistency, SEAL_RECORD_LENGTH, SealKind, SealRecord,
    digest,
};
use crate::disk::Disk;

/// The journal's file name in the archive directory.
pub const JOURNAL_FILE: &str = "integrity.journal";

/// The length of a record, as a file offset.
const RECORD_LENGTH: u64 = SEAL_RECORD_LENGTH as u64;

/// A failure of the integrity journal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntegrityError {
    /// The operating system's error.
    #[error("integrity journal i/o: {0}")]
    Io(#[from] io::Error),
    /// The journal on disk does not chain.
    #[error("integrity journal is inconsistent: {0}")]
    Inconsistent(#[from] Inconsistency),
    /// An earlier append failed part way; reopen the journal to recover.
    #[error("an earlier append failed; the journal must be reopened")]
    Poisoned,
    /// Another handle holds the file's exclusive lock: one writer per
    /// journal or ledger file. Nothing was read or written.
    #[error("the file is open through another handle")]
    Locked,
    /// The journal handle does not hold every record on disk: another
    /// handle appended since it was opened. Nothing was cut or written.
    #[error("the journal was changed through another handle; reopen it")]
    StaleJournal,
    /// A ledger or catalog paired with a journal of another archive
    /// directory: its entries are not this journal's evidence. Nothing was
    /// read, cut or written.
    #[error("the ledger belongs to another archive directory's journal")]
    ForeignLedger,
    /// A ledger handle that does not hold every entry on disk: another
    /// handle appended or cut since it was opened. Nothing was written.
    #[error("the ledger was changed through another handle; reopen it")]
    StaleLedger,
    /// The journal chains record `counter`, whose bytes its ledger does
    /// not hold or holds in a form that does not match.
    #[error("integrity journal record {counter} is chained but missing from its ledger")]
    Unrecorded {
        /// The record's counter.
        counter: u64,
    },
    /// The key registry refused an entry.
    #[error("key registry: {0}")]
    Registry(#[from] super::trust::RegistryError),
    /// The sealing schedule refused a step.
    #[error("sealing schedule: {0}")]
    Schedule(#[from] super::sealer::SealerError),
    /// The journal or a range is too long for its offsets.
    #[error("integrity journal offset overflow")]
    Overflow,
}

/// What [`IntegrityJournal::open`] found.
#[derive(Debug)]
pub struct Opened<D: Disk> {
    /// The journal, ready to append.
    pub journal: IntegrityJournal<D>,
    /// The bytes of a torn tail cut off, 0 when there was none.
    pub truncated: u64,
}

/// The integrity journal of one archive directory.
#[derive(Debug)]
pub struct IntegrityJournal<D: Disk> {
    disk: D,
    file: D::File,
    /// The archive directory the journal is in.
    dir: PathBuf,
    check: ChainCheck,
    /// The identity of the key registry history chained: a running digest
    /// of every key registry record's entry digest, in chain order.
    registry_identity: Digest,
    poisoned: bool,
}

impl<D: Disk> IntegrityJournal<D> {
    /// The journal's path in `dir`.
    #[must_use]
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(JOURNAL_FILE)
    }

    /// Opens the journal of `dir`, creating it empty if it does not exist,
    /// and recovers it: a torn tail is cut off and synced, and the records
    /// before it are checked as a chain.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Io`] for the operating system's error;
    /// [`IntegrityError::Inconsistent`] when the whole records do not
    /// chain or one before the last cannot be read.
    pub fn open(mut disk: D, dir: &Path) -> Result<Opened<D>, IntegrityError> {
        let path = Self::path(dir);
        let file = open_locked(&mut disk, dir, &path)?;
        let length = disk.len(&file)?;
        let whole = length / RECORD_LENGTH;
        let mut check = ChainCheck::new();
        let mut registry_identity = super::trust::EMPTY_REGISTRY;
        let mut kept = whole;
        let mut buf = [0u8; SEAL_RECORD_LENGTH];
        for index in 0..whole {
            let offset = index
                .checked_mul(RECORD_LENGTH)
                .ok_or(IntegrityError::Overflow)?;
            disk.read_at(&file, offset, &mut buf)?;
            let record = match SealRecord::decode(&buf) {
                Ok(record) => record,
                // A last record cut short by a crash: the torn tail.
                Err(DecodeError::Crc { .. }) if index.checked_add(1) == Some(whole) => {
                    kept = index;
                    break;
                }
                Err(error) => return Err(Inconsistency::Malformed { index, error }.into()),
            };
            check.accept(&record)?;
            if record.kind == SealKind::KeyRegistry {
                registry_identity =
                    super::trust::extend_identity(&registry_identity, &record.content);
            }
        }
        let keep = kept
            .checked_mul(RECORD_LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        let truncated = length.checked_sub(keep).ok_or(IntegrityError::Overflow)?;
        if truncated > 0 {
            disk.set_len(&file, keep)?;
            disk.sync(&file)?;
        }
        Ok(Opened {
            journal: Self {
                disk,
                file,
                dir: dir.to_path_buf(),
                check,
                registry_identity,
                poisoned: false,
            },
            truncated,
        })
    }

    /// The counter the next record will carry, which is also the number of
    /// records appended.
    #[must_use]
    #[inline]
    pub const fn next_counter(&self) -> u64 {
        self.check.next_counter()
    }

    /// The identity of the key registry history this journal chains, as
    /// [`super::trust::KeyRegistry::identity`] computes it: only a registry
    /// that applied exactly that history may append the next entry.
    #[must_use]
    #[inline]
    pub const fn key_registry_identity(&self) -> Digest {
        self.registry_identity
    }

    /// The archive directory the journal is in: its ledgers are the ones
    /// in the same directory.
    #[must_use]
    #[inline]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether this handle holds every record on disk: no other handle
    /// appended since it was opened. Recovery that cuts what the journal
    /// does not chain requires it.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Io`] for the operating system's error.
    pub fn is_current(&mut self) -> Result<bool, IntegrityError> {
        let held = self
            .check
            .next_counter()
            .checked_mul(RECORD_LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        Ok(self.disk.len(&self.file)? == held)
    }

    /// Whether an append failed part way: the handle no longer knows how
    /// many records are on disk, so nothing may be derived from it until
    /// the journal is reopened.
    #[must_use]
    #[inline]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// The record digest of the last record, the chain's head.
    #[must_use]
    #[inline]
    pub fn head(&self) -> Digest {
        self.check.head()
    }

    /// Where the sealed ranges of `recording` end, if any is sealed.
    #[must_use]
    pub fn sealed_end(&self, recording: u64) -> Option<u64> {
        self.check.sealed_end(recording)
    }

    /// Every record, read back from disk.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Io`], or [`IntegrityError::Inconsistent`] for a
    /// record that cannot be read.
    pub fn records(&mut self) -> Result<Vec<SealRecord>, IntegrityError> {
        let count = self.next_counter();
        let mut records = Vec::new();
        let mut buf = [0u8; SEAL_RECORD_LENGTH];
        for index in 0..count {
            let offset = index
                .checked_mul(RECORD_LENGTH)
                .ok_or(IntegrityError::Overflow)?;
            self.disk.read_at(&self.file, offset, &mut buf)?;
            let record = SealRecord::decode(&buf)
                .map_err(|error| Inconsistency::Malformed { index, error })?;
            records.push(record);
        }
        Ok(records)
    }

    /// Appends the next record and syncs it.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Inconsistent`] when the record would not chain
    /// (a range that does not follow the recording's last sealed range),
    /// with nothing written; [`IntegrityError::Io`] when the write or the
    /// sync fails, after which the journal is poisoned until reopened;
    /// [`IntegrityError::Poisoned`] after such a failure.
    pub fn append(
        &mut self,
        kind: SealKind,
        subject: u64,
        start: u64,
        end: u64,
        content: Digest,
    ) -> Result<SealRecord, IntegrityError> {
        if self.poisoned {
            return Err(IntegrityError::Poisoned);
        }
        let record = SealRecord {
            kind,
            counter: self.check.next_counter(),
            subject,
            start,
            end,
            content,
            previous: self.check.head(),
        };
        let mut next = self.check.clone();
        next.accept(&record)?;
        let offset = record
            .counter
            .checked_mul(RECORD_LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        let written = self
            .disk
            .write_at(&self.file, offset, &record.encode())
            .and_then(|()| self.disk.sync(&self.file));
        if let Err(error) = written {
            self.poisoned = true;
            return Err(error.into());
        }
        self.check = next;
        if kind == SealKind::KeyRegistry {
            self.registry_identity =
                super::trust::extend_identity(&self.registry_identity, &content);
        }
        Ok(record)
    }

    /// Seals `bytes`, the range of `recording` from `start`: a range of an
    /// open segment, or with `closes` the last range of a segment that
    /// closed.
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`]; [`IntegrityError::Overflow`] when
    /// the range's end does not fit.
    pub fn seal_segment(
        &mut self,
        recording: u64,
        start: u64,
        bytes: &[u8],
        closes: bool,
    ) -> Result<SealRecord, IntegrityError> {
        let end = range_end(start, bytes.len())?;
        let kind = if closes {
            SealKind::ClosedSegment
        } else {
            SealKind::OpenSegment
        };
        self.append(kind, recording, start, end, digest(bytes))
    }

    /// Seals the part of `bytes`, the range of Cluster log `recording`
    /// from `start`, that lies below `commit`: the position just past the
    /// entry at the commit index. Bytes at or above `commit` are never
    /// sealed, since Raft may still truncate them. Returns `None` when no
    /// byte of the range is committed.
    ///
    /// The mapping from the commit index to its position is the Cluster
    /// log's (karyos-cluster); this call only refuses to cross it.
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`].
    pub fn seal_cluster_log(
        &mut self,
        recording: u64,
        start: u64,
        bytes: &[u8],
        commit: u64,
    ) -> Result<Option<SealRecord>, IntegrityError> {
        let end = range_end(start, bytes.len())?.min(commit);
        let Some(length) = end.checked_sub(start).filter(|&length| length > 0) else {
            return Ok(None);
        };
        let length = usize::try_from(length).map_err(|_| IntegrityError::Overflow)?;
        let committed = bytes.get(..length).ok_or(IntegrityError::Overflow)?;
        self.append(
            SealKind::ClusterLog,
            recording,
            start,
            end,
            digest(committed),
        )
        .map(Some)
    }

    /// Chains a catalog change of `recording`: `generation` is the
    /// catalog's generation after the change, `canonical` the change's
    /// canonical bytes.
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`].
    pub fn record_catalog_change(
        &mut self,
        recording: u64,
        generation: u64,
        canonical: &[u8],
    ) -> Result<SealRecord, IntegrityError> {
        self.append(
            SealKind::Catalog,
            recording,
            generation,
            generation,
            digest(canonical),
        )
    }

    /// Chains a change of a copy of `recording` in the copy catalog:
    /// `sequence` is the copy record's sequence, `canonical` its canonical
    /// bytes.
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`].
    pub fn record_copy_change(
        &mut self,
        recording: u64,
        sequence: u64,
        canonical: &[u8],
    ) -> Result<SealRecord, IntegrityError> {
        self.append(
            SealKind::Copy,
            recording,
            sequence,
            sequence,
            digest(canonical),
        )
    }

    /// Chains version `version` of retention policy `policy`, given its
    /// canonical bytes.
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`].
    pub fn record_policy_version(
        &mut self,
        policy: u64,
        version: u64,
        canonical: &[u8],
    ) -> Result<SealRecord, IntegrityError> {
        self.append(
            SealKind::Policy,
            policy,
            version,
            version,
            digest(canonical),
        )
    }

    /// Chains a key registry append: `key_id` is the key's id (the
    /// SHA-256 of its public key), `sequence` the registry record's
    /// sequence, `canonical` its canonical bytes. The record's subject is
    /// the key id's first eight bytes; the full id is in `canonical`.
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`].
    pub fn record_key_registry(
        &mut self,
        key_id: &Digest,
        sequence: u64,
        canonical: &[u8],
    ) -> Result<SealRecord, IntegrityError> {
        let subject = key_id
            .first_chunk::<8>()
            .map_or(0, |bytes| u64::from_le_bytes(*bytes));
        self.append(
            SealKind::KeyRegistry,
            subject,
            sequence,
            sequence,
            digest(canonical),
        )
    }

    /// Chains the purge of `[start, end)` of `recording`, with the digest
    /// of the purged segment as it was sealed, so the deletion itself is
    /// evidence (SPEC.md §8.4, "Purge and legal hold").
    ///
    /// # Errors
    ///
    /// As [`IntegrityJournal::append`].
    pub fn record_purge(
        &mut self,
        recording: u64,
        start: u64,
        end: u64,
        segment_digest: Digest,
    ) -> Result<SealRecord, IntegrityError> {
        self.append(SealKind::Purge, recording, start, end, segment_digest)
    }
}

/// The end of a range of `length` bytes from `start`.
fn range_end(start: u64, length: usize) -> Result<u64, IntegrityError> {
    u64::try_from(length)
        .ok()
        .and_then(|length| start.checked_add(length))
        .ok_or(IntegrityError::Overflow)
}

/// Takes the single-writer lock on a journal or ledger `file`.
pub(super) fn lock<D: Disk>(disk: &mut D, file: &D::File) -> Result<(), IntegrityError> {
    disk.lock(file).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            IntegrityError::Locked
        } else {
            IntegrityError::Io(error)
        }
    })
}

/// Opens the journal or ledger file `path` in `dir` and takes its
/// single-writer lock before anything is read or cut, creating it empty if
/// it does not exist. Creation is exclusive (`create_new`): a file another
/// opener created first is opened, never truncated.
pub(super) fn open_locked<D: Disk>(
    disk: &mut D,
    dir: &Path,
    path: &Path,
) -> Result<D::File, IntegrityError> {
    // Opening loses to a concurrent creation at most once per creator: a
    // few rounds settle it.
    for _ in 0..3 {
        match disk.open(path) {
            Ok(file) => {
                lock(disk, &file)?;
                // The opener may have won the lock from the file's creator
                // before the creator made it durable: whoever holds the
                // lock makes the file and its name durable before use.
                disk.sync(&file)?;
                disk.sync_dir(dir)?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => match disk.create_new(path) {
                Ok(file) => {
                    lock(disk, &file)?;
                    disk.sync(&file)?;
                    disk.sync_dir(dir)?;
                    return Ok(file);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        }
    }
    Err(IntegrityError::Locked)
}
