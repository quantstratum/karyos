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
//! The order of an offload is fixed so that no step drops a recording below
//! its policy:
//!
//! 1. `min_copies` is checked **before** anything is written: the verified
//!    copies elsewhere plus the one about to be made must satisfy it.
//! 2. The local bytes are checked against their seal, so a corrupt local
//!    range is never offloaded as if it were sound.
//! 3. The bytes are written, read back and verified against the seal; only
//!    then is the remote copy recorded [`CopyState::Verified`].
//! 4. `min_copies` is checked again against the catalog, and only then is
//!    the local range removed and its local copy recorded removed.

use std::num::NonZeroU32;

use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::{IntegrityError, IntegrityJournal};
use super::{Digest, Inconsistency, SealRecord, verify_range};
use crate::disk::Disk;

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
    /// Its end, exclusive.
    pub end: u64,
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
        }
    }

    /// The object name: `<archive>/<recording>/<start>-<end>`, in
    /// fixed-width hex so names sort in range order.
    #[must_use]
    pub fn name(&self) -> String {
        let archive: String = self
            .archive
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!(
            "{archive}/{:016x}/{:016x}-{:016x}",
            self.recording, self.start, self.end
        )
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
}

/// The local ranges an offload may remove.
pub trait LocalRanges {
    /// Removes the local bytes of the range `key` names.
    ///
    /// # Errors
    ///
    /// The local storage's error.
    fn remove(&mut self, key: &ObjectKey) -> std::io::Result<()>;
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
    /// Removing the local range failed after the remote copy verified.
    #[error("removing the local range: {0}")]
    Local(#[source] std::io::Error),
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

/// What an offload did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Offloaded {
    /// The catalog change recording the verified remote copy.
    pub remote: SealRecord,
    /// The catalog change recording the local copy removed.
    pub local_removed: SealRecord,
    /// The immutability of the remote copy.
    pub enforcement: Enforcement,
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

    /// Offloads the sealed range `seal` with its local `bytes` to `store`,
    /// then removes it from `local`, in the order of the module's
    /// documentation.
    ///
    /// # Errors
    ///
    /// [`TieringError::BelowMinCopies`] or [`TieringError::LocalMismatch`]
    /// before anything is written; [`TieringError::RemoteMismatch`] or the
    /// store's error with nothing recorded verified and nothing removed;
    /// the catalog's or [`TieringError::Local`] after the remote copy is
    /// recorded, with the local range kept.
    #[allow(
        clippy::too_many_arguments,
        reason = "each is a distinct party of the offload"
    )]
    pub fn offload<D: Disk, O: ObjectStore, L: LocalRanges>(
        &self,
        seal: &SealRecord,
        bytes: &[u8],
        min_copies: NonZeroU32,
        retain_until_ns: u64,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
        store: &mut O,
        local: &mut L,
    ) -> Result<Offloaded, TieringError> {
        if !seal.kind.is_range() {
            return Err(TieringError::NotARange {
                counter: seal.counter,
            });
        }
        // The upload adds a location only when the destination is not this
        // Archive and holds no verified copy of the range yet.
        let adds = self.remote != self.local
            && !copies.current()?.into_iter().any(|copy| {
                copy.location == self.remote
                    && copy.recording == seal.subject
                    && copy.state == CopyState::Verified
                    && copy.start <= seal.start
                    && copy.end >= seal.end
            });
        let after = self
            .copies_elsewhere(copies, seal)?
            .saturating_add(u64::from(adds));
        Self::satisfies(after, min_copies)?;
        verify_range(seal, bytes).map_err(TieringError::LocalMismatch)?;
        let key = ObjectKey::of(self.local, seal);
        let enforcement = store
            .put(&key, bytes, retain_until_ns)
            .map_err(TieringError::Store)?;
        let stored = store.get(&key).map_err(TieringError::Store)?;
        verify_range(seal, &stored).map_err(TieringError::RemoteMismatch)?;
        let remote = copies.record(
            Self::copy(
                seal,
                self.remote,
                retain_until_ns,
                CopyState::Verified,
                enforcement,
            ),
            journal,
        )?;
        Self::satisfies(self.copies_elsewhere(copies, seal)?, min_copies)?;
        // The local copy stops counting before its bytes go: a crash after
        // the removal never leaves bytes that no longer exist counted.
        self.uncount_local(copies, journal, seal)?;
        let local_removed = copies.record(
            Self::copy(
                seal,
                self.local,
                0,
                CopyState::Removed,
                Enforcement::Unsupported,
            ),
            journal,
        )?;
        local.remove(&key).map_err(TieringError::Local)?;
        Ok(Offloaded {
            remote,
            local_removed,
            enforcement,
        })
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
