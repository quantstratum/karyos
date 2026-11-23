// SPDX-License-Identifier: Apache-2.0

//! Tiered storage: offloading sealed ranges to object storage on the
//! control path and restoring them on demand for replay
//! (quantstratum-docs: karyos/SPEC.md §8.4, "Tiered storage"; karyos#669).
//!
//! The object storage client sits behind [`ObjectStore`]; the client crate
//! that implements it over S3 is not a dependency of `karyos-archive`, so
//! nothing on the recording path can reach object storage. Every function
//! here takes the store explicitly and none is called by
//! [`crate::segment::SegmentStore`]'s write path: offload is a control-path
//! operation.
//!
//! The unit is a whole segment, from the oldest (ADR-0104): an offload
//! runs in two steps so that no step drops a recording below its policy or
//! leaves a hole in the local store.
//!
//! 1. [`Tiering::upload_segment`] checks `min_copies` against the copies
//!    the offload would leave, checks each local range against its seal,
//!    then puts one object per range seal and the segment's original index
//!    file, verbatim, and reads each back: each range against its seal, the
//!    index against the SHA-256 computed locally before the upload. Nothing
//!    in the copy catalog, the journal or the local files changes, so a
//!    failure leaves the Archive as it was.
//! 2. [`Tiering::commit_segment`] rechecks `min_copies` (the verified
//!    copies left once the local one is removed, never the local copy),
//!    chains a copy record for each range's remote copy and one offload
//!    record (kind 9) for the segment, stops counting the local copy,
//!    raises the recording's start past the segment durably, and only then
//!    releases the segment's immutability and removes its files.
//!
//! The commit is idempotent: [`Tiering::reconcile`] runs its steps after
//! the offload record again for every offload a crash cut short, and
//! [`reconcile_floors`] raises, before any scan, a start an offload record
//! left unraised.
//!
//! [`Tiering::restore_segment`] works one segment at a time, from the one
//! just below the start downward, and stops at the offload floor: it gets
//! the segment's range objects and index object, verifies them, and hands
//! them to [`SegmentStore::restore_below`], which writes them under
//! temporary names, scans them whole, renames them into place and lowers
//! the start durably. Only then is the restore record (kind 10) chained
//! and the local copies counted verified again. A lowered start whose
//! restore record a crash cut short gets it in [`Tiering::reconcile`]; the
//! floor record's restored mark tells it apart from an offload whose start
//! was never raised.

use std::num::NonZeroU32;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::{IntegrityError, IntegrityJournal};
use super::{Digest, Inconsistency, SealKind, SealRecord, verify_range};
use crate::disk::Disk;
use crate::segment::{SegmentError, SegmentStore};

/// The key of an offloaded range in object storage. Recording ids are
/// each archive's own, so the key names the source archive too: two
/// archives sharing a bucket never write the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectKey {
    /// The source archive's location id.
    pub archive: Digest,
    /// The recording.
    pub recording: u64,
    /// The range's start.
    pub start: u64,
    /// Its end, exclusive; equal to `start` for an index object.
    pub end: u64,
    /// What the object holds.
    pub kind: ObjectKind,
}

/// What an object holds (ADR-0104, decision 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectKind {
    /// A sealed range's bytes.
    Range,
    /// A segment's original index file, verbatim; `start` is the
    /// segment's base.
    Index,
}

impl ObjectKey {
    /// The key of the range `seal` covers in `archive`.
    #[must_use]
    #[inline]
    pub const fn of(archive: Digest, seal: &SealRecord) -> Self {
        Self {
            archive,
            recording: seal.subject,
            start: seal.start,
            end: seal.end,
            kind: ObjectKind::Range,
        }
    }

    /// The key of the original index file of `recording`'s segment at
    /// `base` in `archive`.
    #[must_use]
    #[inline]
    pub const fn index(archive: Digest, recording: u64, base: u64) -> Self {
        Self {
            archive,
            recording,
            start: base,
            end: base,
            kind: ObjectKind::Index,
        }
    }

    /// The object name: `<archive>/<recording>/<start>-<end>` for a range,
    /// `<archive>/<recording>/<base>.idx` for an index, in fixed-width hex
    /// so names sort in position order.
    #[must_use]
    pub fn name(&self) -> String {
        let archive: String = self
            .archive
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        match self.kind {
            ObjectKind::Range => format!(
                "{archive}/{:016x}/{:016x}-{:016x}",
                self.recording, self.start, self.end
            ),
            ObjectKind::Index => {
                format!("{archive}/{:016x}/{:016x}.idx", self.recording, self.start)
            }
        }
    }
}

/// Object storage, as the control path sees it.
pub trait ObjectStore {
    /// Writes `bytes` under `key`, retained until `retain_until_ns`,
    /// returning the immutability that applies to the stored object.
    ///
    /// # Errors
    ///
    /// The storage's error.
    fn put(
        &mut self,
        key: &ObjectKey,
        bytes: &[u8],
        retain_until_ns: u64,
    ) -> std::io::Result<Enforcement>;

    /// Reads the object under `key`.
    ///
    /// # Errors
    ///
    /// The storage's error, including a missing object.
    fn get(&mut self, key: &ObjectKey) -> std::io::Result<Vec<u8>>;

    /// Reads back the object-lock retention of the exact object version
    /// the last [`ObjectStore::put`] of `key` wrote (ADR-0104, decision 2):
    /// `None` when that version holds none. A store without object lock
    /// keeps the default, which reports none.
    ///
    /// # Errors
    ///
    /// The storage's error.
    fn retention(&mut self, key: &ObjectKey) -> std::io::Result<Option<ObjectRetention>> {
        let _ = key;
        Ok(None)
    }
}

/// An object version's object-lock retention, as object storage reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRetention {
    /// The lock mode.
    pub mode: LockMode,
    /// The retain-until date, in ns since the Unix epoch.
    pub retain_until_ns: u64,
}

/// An object-lock mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockMode {
    /// `GOVERNANCE`.
    Governance,
    /// `COMPLIANCE`.
    Compliance,
}

impl ObjectRetention {
    /// Whether it enforces retention up to `deadline_ns`: governance or
    /// compliance mode, retained until at or past the deadline.
    #[must_use]
    pub const fn enforces(&self, deadline_ns: u64) -> bool {
        matches!(self.mode, LockMode::Governance | LockMode::Compliance)
            && self.retain_until_ns >= deadline_ns
    }
}

/// Why an offload or a restore did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TieringError {
    /// The record seals no range of recorded bytes.
    #[error("seal record {counter} seals no range of recorded bytes")]
    NotARange {
        /// The record's counter.
        counter: u64,
    },
    /// The verified copies would not satisfy `min_copies`; nothing was
    /// done.
    #[error("{verified} verified copies elsewhere, {required} required")]
    BelowMinCopies {
        /// The verified copies other than the local one, counting the one
        /// an offload would make.
        verified: u64,
        /// The policy's `min_copies`.
        required: u32,
    },
    /// The local bytes do not match their seal; nothing was offloaded.
    #[error("the local range does not match its seal: {0}")]
    LocalMismatch(Inconsistency),
    /// The object read back, or restored, does not match the seal: it is
    /// not a copy.
    #[error("the remote copy does not match its seal: {0}")]
    RemoteMismatch(Inconsistency),
    /// Object storage failed.
    #[error("object storage: {0}")]
    Store(#[source] std::io::Error),
    /// The index object read back does not match the SHA-256 computed
    /// over the local index before the upload: it is not a copy.
    #[error("the remote index does not match its digest")]
    IndexMismatch,
    /// The segment is not one an offload may take (ADR-0104, decision 1):
    /// not the lowest local segment, the one being written, or not wholly
    /// covered by seals lying inside it. Nothing was done.
    #[error("the segment at {base} is not eligible for offload: {why}")]
    NotEligible {
        /// The segment's base.
        base: u64,
        /// Why.
        why: &'static str,
    },
    /// Releasing a segment file's immutability failed before its removal
    /// (karyos#995): the file stays, and [`Tiering::reconcile`] retries.
    #[error("releasing the immutability of {path}: {error}", path = path.display())]
    Release {
        /// The file.
        path: std::path::PathBuf,
        /// The backend's error.
        #[source]
        error: std::io::Error,
    },
    /// The segment store failed.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The copy catalog or the integrity journal failed.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
}

/// Where tiering's copies are catalogued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tiering {
    /// This Archive's location.
    pub local: Digest,
    /// The object storage location.
    pub remote: Digest,
}

/// One segment an offload takes, as read from the local store: its seals
/// and its files' bytes.
#[derive(Debug, Clone, Copy)]
pub struct LocalSegment<'a> {
    /// The recording.
    pub recording: u64,
    /// The segment's base.
    pub base: u64,
    /// The range it holds, `[start, end)`.
    pub start: u64,
    /// Its end, exclusive: the segment's end.
    pub end: u64,
    /// The range seals of the recording overlapping it, in order.
    pub seals: &'a [SealRecord],
    /// The data file's bytes from the base.
    pub data: &'a [u8],
    /// The original index file's bytes.
    pub index: &'a [u8],
}

/// What [`Tiering::upload_segment`] put and read back: every object
/// verified, nothing recorded yet.
///
/// Opaque: only [`Tiering::upload_segment`] makes one, and
/// [`Tiering::commit_segment`] commits it only through the same archive and
/// destination, for the segment and seals it was made from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Uploaded {
    local: Digest,
    remote: Digest,
    recording: u64,
    base: u64,
    start: u64,
    end: u64,
    ranges: Vec<(SealRecord, Enforcement)>,
    index_digest: Digest,
    index: Enforcement,
}

impl Uploaded {
    /// The recording.
    #[must_use]
    pub const fn recording(&self) -> u64 {
        self.recording
    }

    /// The segment's base.
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// The range it holds, `[start, end)`.
    #[must_use]
    pub const fn range(&self) -> (u64, u64) {
        (self.start, self.end)
    }

    /// Each range seal with the immutability of its remote copy.
    #[must_use]
    pub fn ranges(&self) -> &[(SealRecord, Enforcement)] {
        &self.ranges
    }

    /// The SHA-256 of the original index file, computed before the upload.
    #[must_use]
    pub const fn index_digest(&self) -> Digest {
        self.index_digest
    }

    /// The immutability of the index object.
    #[must_use]
    pub const fn index(&self) -> Enforcement {
        self.index
    }
}

/// Releases through an [`super::copies::ImmutabilityBackend`].
pub struct Releasing<'a>(pub &'a mut dyn super::copies::ImmutabilityBackend);

impl std::fmt::Debug for Releasing<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Releasing")
    }
}

impl Release for Releasing<'_> {
    fn release(&mut self, path: &Path) -> std::io::Result<()> {
        self.0.release(path)
    }
}

/// The release of a segment file's immutability before its removal
/// (karyos#995).
pub trait Release {
    /// Releases the immutability of `path`.
    ///
    /// # Errors
    ///
    /// The backend's error.
    fn release(&mut self, path: &Path) -> std::io::Result<()>;
}

/// No immutability to release.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRelease;

impl Release for NoRelease {
    fn release(&mut self, _: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

/// The SHA-256 of an index file's bytes.
#[must_use]
pub fn index_digest(index: &[u8]) -> Digest {
    Sha256::digest(index).into()
}

/// The offload records of `records` not reversed by a later restore
/// record of the same range, by recording, in chain order: the segments
/// the chain holds remote (ADR-0104, decision 5).
#[must_use]
pub fn offloaded(records: &[SealRecord]) -> std::collections::BTreeMap<u64, Vec<SealRecord>> {
    let mut held: std::collections::BTreeMap<u64, Vec<SealRecord>> =
        std::collections::BTreeMap::new();
    for record in records {
        match record.kind {
            SealKind::Offload => held.entry(record.subject).or_default().push(*record),
            SealKind::Restore => {
                if let Some(list) = held.get_mut(&record.subject) {
                    list.retain(|offload| {
                        (offload.start, offload.end) != (record.start, record.end)
                    });
                }
            }
            _ => {}
        }
    }
    held.retain(|_, list| !list.is_empty());
    held
}

/// Raises, before any scan, the start of each recording in `dir` whose
/// offload records the chain holds past its floor record's start
/// (ADR-0104, decision 4): an offload whose start a crash left unraised.
/// Returns the recordings it raised.
///
/// # Errors
///
/// The segment store's errors.
pub fn reconcile_floors<S: Disk>(
    disk: &mut S,
    dir: &Path,
    records: &[SealRecord],
) -> Result<Vec<u64>, SegmentError> {
    let mut raised = Vec::new();
    for (recording, mut offloads) in offloaded(records) {
        // A restore whose record a crash cut short lowered the start onto
        // its offload's: that one is local again, never raised over.
        if let Some((start, _, true)) = crate::segment::floor_of(disk, dir, recording)? {
            offloads.retain(|offload| offload.start < start);
        }
        let (Some(lowest), Some(end)) = (
            offloads.iter().map(|offload| offload.start).min(),
            offloads.iter().map(|offload| offload.end).max(),
        ) else {
            continue;
        };
        if crate::segment::raise_floor(disk, dir, recording, end, lowest)? {
            raised.push(recording);
        }
    }
    Ok(raised)
}

impl Tiering {
    /// The verified copies of `seal`'s range other than the local one.
    ///
    /// # Errors
    ///
    /// The copy catalog's error.
    pub fn copies_elsewhere<D: Disk>(
        &self,
        copies: &CopyCatalog<D>,
        seal: &SealRecord,
    ) -> Result<u64, IntegrityError> {
        let local = copies
            .current()?
            .into_iter()
            .any(|copy| self.is_local_verified(&copy, seal));
        let all = copies.verified_copies(seal.subject, seal.start, seal.end)?;
        Ok(all.saturating_sub(u64::from(local)))
    }

    fn is_local_verified(&self, copy: &CopyRecord, seal: &SealRecord) -> bool {
        copy.location == self.local
            && copy.recording == seal.subject
            && copy.state == CopyState::Verified
            && copy.start <= seal.start
            && copy.end >= seal.end
    }

    /// Whether an upload of `seal`'s range to the remote location adds a
    /// location: the destination is not this Archive and holds no
    /// verified copy of the range yet.
    fn adds<D: Disk>(
        &self,
        copies: &CopyCatalog<D>,
        seal: &SealRecord,
    ) -> Result<bool, IntegrityError> {
        Ok(self.remote != self.local
            && !copies
                .current()?
                .into_iter()
                .any(|copy| self.is_remote_verified(&copy, seal)))
    }

    fn is_remote_verified(&self, copy: &CopyRecord, seal: &SealRecord) -> bool {
        copy.location == self.remote
            && copy.recording == seal.subject
            && copy.state == CopyState::Verified
            && copy.start <= seal.start
            && copy.end >= seal.end
    }

    /// Checks that every range of `seals` keeps `min_copies` verified
    /// copies once the local one is removed: those elsewhere, plus the
    /// remote one the offload makes when it adds a location.
    fn check_copies<D: Disk>(
        &self,
        copies: &CopyCatalog<D>,
        seals: &[SealRecord],
        min_copies: NonZeroU32,
    ) -> Result<(), TieringError> {
        for seal in seals {
            let after = self
                .copies_elsewhere(copies, seal)?
                .saturating_add(u64::from(self.adds(copies, seal)?));
            Self::satisfies(after, min_copies)?;
        }
        Ok(())
    }

    /// Checks that `seals` cover `[start, end)` of the segment at `base`
    /// without a gap, each lying wholly inside the segment (ADR-0104,
    /// decision 1).
    fn check_covered(
        base: u64,
        start: u64,
        end: u64,
        seals: &[SealRecord],
    ) -> Result<(), TieringError> {
        let refuse = |why| TieringError::NotEligible { base, why };
        let mut at = start;
        for seal in seals {
            if !seal.kind.is_range() {
                return Err(TieringError::NotARange {
                    counter: seal.counter,
                });
            }
            if seal.start < base || seal.end > end {
                return Err(refuse("a seal crosses the segment's boundary"));
            }
            if seal.start != at {
                return Err(refuse("the seals do not cover the segment without a gap"));
            }
            at = seal.end;
        }
        if at != end {
            return Err(refuse("the seals do not reach the segment's end"));
        }
        Ok(())
    }

    /// Uploads `segment` and reads it back (ADR-0104, decision 3): one
    /// object per range seal and its original index, each verified on
    /// read back. Nothing is recorded and nothing local changes.
    ///
    /// # Errors
    ///
    /// [`TieringError::NotEligible`], [`TieringError::BelowMinCopies`] or
    /// [`TieringError::LocalMismatch`] before anything is written;
    /// [`TieringError::RemoteMismatch`], [`TieringError::IndexMismatch`]
    /// or the store's error after, with nothing recorded.
    pub fn upload_segment<D: Disk, O: ObjectStore>(
        &self,
        segment: &LocalSegment<'_>,
        min_copies: NonZeroU32,
        retain_until_ns: u64,
        copies: &CopyCatalog<D>,
        store: &mut O,
    ) -> Result<Uploaded, TieringError> {
        Self::check_covered(segment.base, segment.start, segment.end, segment.seals)?;
        self.check_copies(copies, segment.seals, min_copies)?;
        let mut ranges = Vec::with_capacity(segment.seals.len());
        let mut parts = Vec::with_capacity(segment.seals.len());
        for seal in segment.seals {
            let bytes = Self::slice(segment, seal)?;
            verify_range(seal, bytes).map_err(TieringError::LocalMismatch)?;
            parts.push((*seal, bytes));
        }
        // The digest the offload record carries, computed before the upload.
        let digest = index_digest(segment.index);
        for (seal, bytes) in parts {
            let key = ObjectKey::of(self.local, &seal);
            let enforcement = store
                .put(&key, bytes, retain_until_ns)
                .map_err(TieringError::Store)?;
            let stored = store.get(&key).map_err(TieringError::Store)?;
            verify_range(&seal, &stored).map_err(TieringError::RemoteMismatch)?;
            ranges.push((seal, enforcement));
        }
        let key = ObjectKey::index(self.local, segment.recording, segment.base);
        let index = store
            .put(&key, segment.index, retain_until_ns)
            .map_err(TieringError::Store)?;
        let stored = store.get(&key).map_err(TieringError::Store)?;
        if index_digest(&stored) != digest {
            return Err(TieringError::IndexMismatch);
        }
        Ok(Uploaded {
            local: self.local,
            remote: self.remote,
            recording: segment.recording,
            base: segment.base,
            start: segment.start,
            end: segment.end,
            ranges,
            index_digest: digest,
            index,
        })
    }

    /// The local bytes of `seal` in `segment`'s data file.
    fn slice<'a>(segment: &LocalSegment<'a>, seal: &SealRecord) -> Result<&'a [u8], TieringError> {
        let refuse = |why| TieringError::NotEligible {
            base: segment.base,
            why,
        };
        let offset = |position: u64| {
            position
                .checked_sub(segment.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or_else(|| refuse("a seal crosses the segment's boundary"))
        };
        let (from, to) = (offset(seal.start)?, offset(seal.end)?);
        segment
            .data
            .get(from..to)
            .ok_or_else(|| refuse("the data file is shorter than its seals"))
    }

    /// Commits an uploaded segment (ADR-0104, decision 4): rechecks
    /// `min_copies`, chains a copy record per range and the offload
    /// record, stops counting the local copy, raises the start past the
    /// segment durably, then releases and removes its files. Returns the
    /// offload record. Idempotent: a segment already committed is only
    /// finished.
    ///
    /// # Errors
    ///
    /// [`TieringError::NotEligible`] or [`TieringError::BelowMinCopies`]
    /// with nothing recorded; the catalog's, the store's or
    /// [`TieringError::Release`] after, which [`Tiering::reconcile`]
    /// completes.
    #[allow(
        clippy::too_many_arguments,
        reason = "each is a distinct party of the commit"
    )]
    pub fn commit_segment<D: Disk, S: Disk, R: Release>(
        &self,
        uploaded: &Uploaded,
        min_copies: NonZeroU32,
        retain_until_ns: u64,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        segments: &mut SegmentStore<S>,
        release: &mut R,
    ) -> Result<SealRecord, TieringError> {
        let seals: Vec<SealRecord> = uploaded.ranges.iter().map(|(seal, _)| *seal).collect();
        let records = journal.records()?;
        let refuse = |why| TieringError::NotEligible {
            base: uploaded.base,
            why,
        };
        // The receipt binds the archive, the destination and the segment:
        // a commit never records a copy at a location that did not get
        // the objects (ADR-0104, decisions 3 and 4).
        if (uploaded.local, uploaded.remote) != (self.local, self.remote) {
            return Err(refuse("uploaded through another archive or destination"));
        }
        let chained: Vec<SealRecord> = records
            .iter()
            .filter(|record| {
                record.kind.is_range()
                    && record.subject == uploaded.recording
                    && record.start < uploaded.end
                    && record.end > uploaded.start
            })
            .copied()
            .collect();
        if chained != seals || segments.recording() != uploaded.recording {
            return Err(refuse("the upload's seals are not the segment's"));
        }
        // A segment a purge cut keeps index entries below the start whose
        // bytes no seal holds: it could never be restored whole, so it is
        // never offloaded (ADR-0104, decisions 1 and 5).
        if uploaded.start > uploaded.base
            && records.iter().any(|record| {
                record.kind == SealKind::Purge
                    && record.subject == uploaded.recording
                    && record.end > uploaded.base
            })
        {
            return Err(refuse("a purge cut the segment"));
        }
        let committed = offloaded(&records)
            .get(&uploaded.recording)
            .and_then(|list| {
                list.iter()
                    .find(|offload| (offload.start, offload.end) == (uploaded.start, uploaded.end))
                    .copied()
            });
        let record = if let Some(record) = committed {
            if record.content != uploaded.index_digest {
                return Err(TieringError::IndexMismatch);
            }
            record
        } else {
            if segments.recording() != uploaded.recording
                || segments.lowest_finished_segment() != Some((uploaded.start, uploaded.end))
            {
                return Err(TieringError::NotEligible {
                    base: uploaded.base,
                    why: "not the lowest finished local segment",
                });
            }
            self.check_copies(copies, &seals, min_copies)?;
            // A copy record for every range, even one the destination
            // already held: the verifier finds the offload's custody
            // change between each seal and its offload record (decision 4).
            for (seal, enforcement) in &uploaded.ranges {
                copies.record(
                    Self::copy(
                        seal,
                        self.remote,
                        retain_until_ns,
                        CopyState::Verified,
                        *enforcement,
                    ),
                    journal,
                )?;
            }
            // An offload record at a start a restore moved would read as
            // a restore cut short: the mark goes first.
            segments.clear_restored()?;
            journal.record_offload(
                uploaded.recording,
                uploaded.start,
                uploaded.end,
                uploaded.index_digest,
            )?
        };
        self.finish(&record, &seals, copies, journal, segments, release)?;
        Ok(record)
    }

    /// The steps of a commit after its offload record: the local copy
    /// stops counting, the start rises past the segment, its files are
    /// released and removed. Each is idempotent.
    fn finish<D: Disk, S: Disk, R: Release>(
        &self,
        record: &SealRecord,
        seals: &[SealRecord],
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        segments: &mut SegmentStore<S>,
        release: &mut R,
    ) -> Result<(), TieringError> {
        for seal in seals {
            // The local copy stops counting before its bytes go.
            self.uncount_local(copies, journal, seal)?;
            let counted = copies
                .current()?
                .into_iter()
                .any(|copy| self.is_local_verified(&copy, seal));
            if counted {
                copies.record(
                    Self::copy(
                        seal,
                        self.local,
                        0,
                        CopyState::Removed,
                        Enforcement::Unsupported,
                    ),
                    journal,
                )?;
            }
        }
        if segments.start() < record.end {
            if segments.lowest_finished_segment().map(|(_, end)| end) != Some(record.end) {
                return Err(TieringError::NotEligible {
                    base: segments.geometry().base_of(record.start),
                    why: "not the lowest finished local segment",
                });
            }
            let _ = segments.raise_start_for_offload()?;
        }
        Self::remove_below(segments, release)
    }

    /// Releases and removes the files left below the start: a removal a
    /// crash cut short, as for a purge (karyos#1121).
    fn remove_below<S: Disk, R: Release>(
        segments: &mut SegmentStore<S>,
        release: &mut R,
    ) -> Result<(), TieringError> {
        let left = segments.files_left_below_floor()?;
        if left.is_empty() {
            return Ok(());
        }
        for (_, path, data) in &left {
            if *data {
                release
                    .release(path)
                    .map_err(|error| TieringError::Release {
                        path: path.clone(),
                        error,
                    })?;
            }
        }
        let bases: Vec<u64> = left.iter().map(|(base, _, _)| *base).collect();
        segments.remove_left_below_floor(&bases)?;
        Ok(())
    }

    /// Reconciles `segments`' recording on open (ADR-0104, decision 4):
    /// for each offload record the chain holds, the local copy stops
    /// counting and the start is raised past it; files below the start
    /// are released and removed. Files with no offload record are a
    /// segment never committed, and stay.
    ///
    /// # Errors
    ///
    /// As [`Tiering::commit_segment`] after its offload record.
    pub fn reconcile<D: Disk, S: Disk, R: Release>(
        &self,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        segments: &mut SegmentStore<S>,
        release: &mut R,
    ) -> Result<(), TieringError> {
        let records = journal.records()?;
        let recording = segments.recording();
        let mut offloads = offloaded(&records).remove(&recording).unwrap_or_default();
        // A lowered start with no restore record: the restore a crash cut
        // short after the start moved (ADR-0104, decision 6).
        if segments.restored()
            && let Some(position) = offloads
                .iter()
                .position(|offload| offload.start == segments.start())
        {
            let offload = offloads.remove(position);
            let seals = Self::seals_of(&records, &offload);
            self.record_restored(&offload, &seals, copies, journal)?;
        }
        for offload in offloads {
            let seals = Self::seals_of(&records, &offload);
            self.finish(&offload, &seals, copies, journal, segments, release)?;
        }
        // A restore record whose copy records a crash cut short: the
        // segment is local again, so its copies are counted again.
        let mut last: std::collections::BTreeMap<(u64, u64), &SealRecord> =
            std::collections::BTreeMap::new();
        for record in records.iter().filter(|record| {
            record.subject == recording
                && matches!(record.kind, SealKind::Offload | SealKind::Restore)
        }) {
            last.insert((record.start, record.end), record);
        }
        for restore in last
            .values()
            .filter(|record| record.kind == SealKind::Restore)
        {
            if segments.start() <= restore.start {
                let seals = Self::seals_of(&records, restore);
                self.count_restored(&seals, copies, journal)?;
            }
        }
        Self::remove_below(segments, release)
    }

    /// The range seals an offload record's segment holds.
    fn seals_of(records: &[SealRecord], offload: &SealRecord) -> Vec<SealRecord> {
        records
            .iter()
            .filter(|record| {
                record.kind.is_range()
                    && record.subject == offload.subject
                    && record.start >= offload.start
                    && record.end <= offload.end
            })
            .copied()
            .collect()
    }

    /// Restores the offloaded segment just below `segments`' start from
    /// `store` (ADR-0104, decision 6), returning the restore record. The
    /// index object must match the offload record's digest and each range
    /// object its seal; the store then rebuilds the segment and lowers the
    /// start, and only after that is the restore record chained and the
    /// local copies recorded verified again.
    ///
    /// # Errors
    ///
    /// [`TieringError::NotEligible`] when no offload record ends at the
    /// start, the store's error, [`TieringError::IndexMismatch`] or
    /// [`TieringError::RemoteMismatch`] with nothing changed; the segment
    /// store's [`SegmentError::InvalidRestore`] when the files do not scan
    /// whole; the catalog's after the start moved, which
    /// [`Tiering::reconcile`] completes.
    pub fn restore_segment<D: Disk, S: Disk, O: ObjectStore>(
        &self,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        segments: &mut SegmentStore<S>,
        store: &mut O,
    ) -> Result<SealRecord, TieringError> {
        let records = journal.records()?;
        let recording = segments.recording();
        let start = segments.start();
        let base = start.saturating_sub(segments.geometry().segment_length());
        let refuse = |why| TieringError::NotEligible { base, why };
        let offload = offloaded(&records)
            .remove(&recording)
            .unwrap_or_default()
            .into_iter()
            .find(|offload| offload.end == start)
            .ok_or_else(|| refuse("no offloaded segment ends at the start"))?;
        if segments.geometry().base_of(offload.start) != base
            || offload.start < segments.lowest_retained()
        {
            return Err(refuse(
                "the offload record is not the segment below the start",
            ));
        }
        let index = store
            .get(&ObjectKey::index(self.local, recording, base))
            .map_err(TieringError::Store)?;
        if index_digest(&index) != offload.content {
            return Err(TieringError::IndexMismatch);
        }
        let seals = Self::seals_of(&records, &offload);
        Self::check_covered(base, offload.start, offload.end, &seals)?;
        let length = usize::try_from(offload.end.saturating_sub(base))
            .map_err(|_| refuse("the segment does not fit in memory"))?;
        let mut data = vec![0u8; length];
        for seal in &seals {
            let bytes = store
                .get(&ObjectKey::of(self.local, seal))
                .map_err(TieringError::Store)?;
            verify_range(seal, &bytes).map_err(TieringError::RemoteMismatch)?;
            let from = usize::try_from(seal.start.saturating_sub(base))
                .map_err(|_| refuse("a seal crosses the segment's boundary"))?;
            let to = from
                .checked_add(bytes.len())
                .ok_or_else(|| refuse("a seal crosses the segment's boundary"))?;
            data.get_mut(from..to)
                .ok_or_else(|| refuse("a seal crosses the segment's boundary"))?
                .copy_from_slice(&bytes);
        }
        let restored = segments.restore_below(&data, &index)?;
        if restored != offload.start {
            return Err(refuse("the restored start is not the offload record's"));
        }
        self.record_restored(&offload, &seals, copies, journal)
    }

    /// Chains the restore record of `offload` and records the local copy
    /// of each of its ranges verified again: the restored segment counts
    /// as a local copy only from here.
    fn record_restored<D: Disk>(
        &self,
        offload: &SealRecord,
        seals: &[SealRecord],
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<SealRecord, TieringError> {
        let record =
            journal.record_restore(offload.subject, offload.start, offload.end, offload.content)?;
        self.count_restored(seals, copies, journal)?;
        Ok(record)
    }

    /// Records the local copy of each of `seals` verified, unless it
    /// already counts: idempotent, so a crash between the restore record
    /// and its copy records is finished by [`Tiering::reconcile`].
    fn count_restored<D: Disk>(
        &self,
        seals: &[SealRecord],
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<(), TieringError> {
        for seal in seals {
            let counted = copies
                .current()?
                .into_iter()
                .any(|copy| self.is_local_verified(&copy, seal));
            if counted {
                continue;
            }
            copies.record(
                Self::copy(
                    seal,
                    self.local,
                    0,
                    CopyState::Verified,
                    Enforcement::Unsupported,
                ),
                journal,
            )?;
        }
        Ok(())
    }

    /// Stops every verified local copy overlapping `seal`'s range from
    /// counting: one covering more than the range is removed and its parts
    /// outside the range recorded verified again.
    fn uncount_local<D: Disk>(
        &self,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        seal: &SealRecord,
    ) -> Result<(), TieringError> {
        let overlapping: Vec<CopyRecord> = copies
            .current()?
            .into_iter()
            .filter(|copy| {
                copy.location == self.local
                    && copy.recording == seal.subject
                    && copy.state == CopyState::Verified
                    && copy.start < seal.end
                    && seal.start < copy.end
                    && (copy.start, copy.end) != (seal.start, seal.end)
            })
            .collect();
        for copy in overlapping {
            copies.record(
                CopyRecord {
                    state: CopyState::Removed,
                    ..copy
                },
                journal,
            )?;
            for (start, end) in [(copy.start, seal.start), (seal.end, copy.end)] {
                if start < end {
                    copies.record(CopyRecord { start, end, ..copy }, journal)?;
                }
            }
        }
        Ok(())
    }

    /// Restores the offloaded range `seal` from `store` for replay,
    /// returning its bytes only once they verify against the seal.
    ///
    /// # Errors
    ///
    /// The store's error, or [`TieringError::RemoteMismatch`].
    pub fn restore<O: ObjectStore>(
        &self,
        seal: &SealRecord,
        store: &mut O,
    ) -> Result<Vec<u8>, TieringError> {
        if !seal.kind.is_range() {
            return Err(TieringError::NotARange {
                counter: seal.counter,
            });
        }
        let bytes = store
            .get(&ObjectKey::of(self.local, seal))
            .map_err(TieringError::Store)?;
        verify_range(seal, &bytes).map_err(TieringError::RemoteMismatch)?;
        Ok(bytes)
    }

    fn satisfies(verified: u64, min_copies: NonZeroU32) -> Result<(), TieringError> {
        if verified < u64::from(min_copies.get()) {
            return Err(TieringError::BelowMinCopies {
                verified,
                required: min_copies.get(),
            });
        }
        Ok(())
    }

    const fn copy(
        seal: &SealRecord,
        location: Digest,
        retain_until_ns: u64,
        state: CopyState,
        enforcement: Enforcement,
    ) -> CopyRecord {
        CopyRecord {
            sequence: 0,
            recording: seal.subject,
            start: seal.start,
            end: seal.end,
            location,
            digest: seal.content,
            retain_until_ns,
            state,
            enforcement,
            profile: crate::integrity::copies::ArrivalProfile::Local,
        }
    }
}
