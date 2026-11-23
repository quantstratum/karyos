// SPDX-License-Identifier: Apache-2.0

//! Offline tiering of an Archive directory no `karyosd` holds (ADR-0104,
//! decisions 2 and 9; karyos#1113): what the `karyos-tiering` binary runs.
//!
//! [`Offline::open`] takes the Archive's own locks (the integrity journal,
//! the operations journal, the pending holds' markers and the policy
//! book) and never waits for them: a live directory is refused with
//! [`OfflineError::Live`] and nothing changes. The object store is the
//! caller's, behind [`ObjectStore`], so nothing here reaches object
//! storage by itself.
//!
//! Before any offload commits, the preconditions fail closed:
//!
//! - no purge intent of the Archive is unresolved;
//! - the recording has no legal hold, pending, in force or unknown;
//! - under a retention deadline, the store writes under object lock and
//!   each object version read back is retained in governance or compliance
//!   mode at or past the deadline; otherwise the segment is skipped and
//!   reported, and nothing is committed;
//! - the first tiering commit of a directory needs the operator's
//!   acceptance of the downgrade break (ADR-0104, decision 8).

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use super::Digest;
use super::copies::{CopyCatalog, CopyRecord, CopyState, ImmutabilityBackend};
use super::journal::{IntegrityError, IntegrityJournal};
use super::ledger::Ledger;
use super::retention::{
    MARKER_LENGTH, OPERATION_LENGTH, OPERATIONS_FILE, PENDING_HOLDS_FILE, PolicyBook, Retention,
};
use super::tiering::{
    LocalSegment, ObjectKey, ObjectStore, Release, Tiering, TieringError, index_digest, offloaded,
    reconcile_floors,
};
use super::{SealRecord, verify_range};
use crate::catalog::{self, CatalogError, Recording};
use crate::control::HoldState;
use crate::disk::Disk;
use crate::segment::{SegmentError, SegmentStore, SyncPolicy};

/// Why an offline run refused or failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OfflineError {
    /// A running Archive holds the directory's locks: nothing changed.
    #[error("the archive directory is in use by a running karyosd: stop it first")]
    Live,
    /// The location given is not the one the Archive records for its own
    /// copies.
    #[error("--location {given} is not this Archive's location {recorded}")]
    LocationMismatch {
        /// The location given, in hex.
        given: String,
        /// The location the Archive records, in hex.
        recorded: String,
    },
    /// The Archive records no local copy, so its location cannot be
    /// checked.
    #[error("the Archive records no local copy: run karyosd with --archive-copy-location first")]
    NoLocalCopy,
    /// The Archive records local copies at more than one location.
    #[error("the Archive records local copies at several locations")]
    AmbiguousLocation,
    /// No recording has this id.
    #[error("no recording {0}")]
    UnknownRecording(u64),
    /// The recording is still recording.
    #[error("recording {0} has not stopped")]
    NotStopped(u64),
    /// A purge intent of the Archive is unresolved (ADR-0104, decision 2).
    #[error("purge intent {id} of recording {recording} is unresolved: resolve it first")]
    PurgeIntent {
        /// The intent.
        id: u64,
        /// Its recording.
        recording: u64,
    },
    /// The recording has a legal hold in some state (ADR-0104, decision 2).
    #[error("recording {recording} has a legal hold ({state}): it is never tiered")]
    LegalHold {
        /// The recording.
        recording: u64,
        /// The hold's state.
        state: &'static str,
    },
    /// No retention policy applies and no `min_copies` was given.
    #[error("no retention policy applies to recording {0}: pass --min-copies")]
    NoMinCopies(u64),
    /// The first tiering commit of this directory needs the operator's
    /// acceptance of the downgrade break (ADR-0104, decision 8).
    #[error(
        "tiering makes this directory unreadable by builds before ADR-0104 (seal kinds 9 and 10): pass --accept-downgrade-break"
    )]
    DowngradeBreak,
    /// The integrity journal, a ledger or the copy catalog failed.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// The catalog failed.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// The segment store failed.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// Tiering failed.
    #[error(transparent)]
    Tiering(#[from] TieringError),
    /// A file could not be read.
    #[error("reading {path}: {error}", path = path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The error.
        #[source]
        error: std::io::Error,
    },
}

impl OfflineError {
    fn locked(error: IntegrityError) -> Self {
        match error {
            IntegrityError::Locked => Self::Live,
            other => Self::Integrity(other),
        }
    }
}

/// How an offload runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffloadOptions {
    /// `min_copies` when no retention policy applies.
    pub min_copies: Option<NonZeroU32>,
    /// The operator accepted the downgrade break of a first tiering.
    pub accept_downgrade_break: bool,
    /// The most segments to offload; `None` for every eligible one.
    pub limit: Option<u64>,
}

/// Why an offload stopped before a segment, which stays local.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stopped {
    /// No finished segment is left: the one being written stays.
    NoneLeft,
    /// The limit was reached.
    Limit,
    /// The segment is not eligible (ADR-0104, decision 1).
    NotEligible {
        /// The segment's base.
        base: u64,
        /// Why.
        why: &'static str,
    },
    /// An object version read back does not enforce the retention
    /// deadline (ADR-0104, decision 2): the segment is skipped and
    /// nothing is committed.
    LockNotEnforced {
        /// The segment's base.
        base: u64,
        /// The object.
        object: String,
    },
    /// The copies would fall below `min_copies`.
    BelowMinCopies {
        /// The segment's base.
        base: u64,
        /// The verified copies left.
        verified: u64,
        /// The policy's `min_copies`.
        required: u32,
    },
}

/// What an offload did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct OffloadReport {
    /// The offload records chained, in order.
    pub offloaded: Vec<SealRecord>,
    /// Why it stopped.
    pub stopped: Stopped,
}

/// A remote object's state, as `karyos-tiering verify` reports it
/// (ADR-0104, decision 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectState {
    /// It matches its seal or its recorded index digest.
    Verified,
    /// Object storage does not hold it.
    Missing,
    /// It does not match.
    Corrupt,
}

impl ObjectState {
    /// The state's name in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
        }
    }
}

/// One remote object's verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReport {
    /// The object's name.
    pub object: String,
    /// The recording.
    pub recording: u64,
    /// The range it holds, or the segment's base twice for an index.
    pub start: u64,
    /// Its end.
    pub end: u64,
    /// Its state.
    pub state: ObjectState,
}

/// Releases immutability through the platform's backend before a removal
/// (karyos#995).
struct Backend<'a>(&'a mut dyn ImmutabilityBackend);

impl Release for Backend<'_> {
    fn release(&mut self, path: &Path) -> std::io::Result<()> {
        self.0.release(path)
    }
}

/// An Archive directory opened offline, its locks held.
pub struct Offline<D: Disk> {
    disk: D,
    dir: PathBuf,
    journal: IntegrityJournal<D>,
    copies: CopyCatalog<D>,
    retention: Retention<Ledger<D, OPERATION_LENGTH>, D>,
    book: PolicyBook<D>,
    recordings: Vec<Recording>,
    immutability: Box<dyn ImmutabilityBackend>,
}

impl<D: Disk> std::fmt::Debug for Offline<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offline")
            .field("dir", &self.dir)
            .field("recordings", &self.recordings.len())
            .finish_non_exhaustive()
    }
}

/// The hex of a location.
#[must_use]
pub fn hex(digest: &Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_file<D: Disk>(disk: &mut D, path: &Path) -> Result<Vec<u8>, OfflineError> {
    let read = |disk: &mut D| -> std::io::Result<Vec<u8>> {
        let file = disk.open_read(path)?;
        let length = usize::try_from(disk.len(&file)?)
            .map_err(|_| std::io::Error::other("the file does not fit in memory"))?;
        let mut bytes = vec![0u8; length];
        disk.read_at(&file, 0, &mut bytes)?;
        Ok(bytes)
    };
    read(disk).map_err(|error| OfflineError::Read {
        path: path.to_path_buf(),
        error,
    })
}

impl<D: Disk + Clone> Offline<D> {
    /// Opens the Archive in `dir` offline: takes its locks without
    /// waiting, raises before any scan a start an offload record left
    /// unraised, and reads its catalog, holds, intents and policies.
    /// `immutability` releases a segment's files before their removal.
    ///
    /// # Errors
    ///
    /// [`OfflineError::Live`] when a running Archive holds a lock, with
    /// nothing changed; the journals', the ledgers' and the catalog's
    /// errors.
    pub fn open(
        disk: D,
        dir: &Path,
        immutability: Box<dyn ImmutabilityBackend>,
    ) -> Result<Self, OfflineError> {
        let mut journal = IntegrityJournal::open(disk.clone(), dir)
            .map_err(OfflineError::locked)?
            .journal;
        let operations = Ledger::<D, OPERATION_LENGTH>::open(disk.clone(), dir, OPERATIONS_FILE)
            .map_err(OfflineError::locked)?;
        let pending = Ledger::<D, MARKER_LENGTH>::open(disk.clone(), dir, PENDING_HOLDS_FILE)
            .map_err(OfflineError::locked)?;
        let book =
            PolicyBook::open(disk.clone(), dir, &mut journal).map_err(OfflineError::locked)?;
        let copies = CopyCatalog::open(disk.clone(), dir, &mut journal)?;
        if journal.tiered() {
            let records = journal.records()?;
            let _ = reconcile_floors(&mut disk.clone(), dir, &records)?;
        }
        let records = operations.entries().to_vec();
        let retention = Retention::recover(operations, Some(&records), pending);
        let recordings = catalog::list(disk.clone(), dir)?.recordings;
        Ok(Self {
            disk,
            dir: dir.to_path_buf(),
            journal,
            copies,
            retention,
            book,
            recordings,
            immutability,
        })
    }

    /// The recordings of the catalog.
    #[must_use]
    pub fn recordings(&self) -> &[Recording] {
        &self.recordings
    }

    /// The integrity journal, read only.
    #[must_use]
    pub const fn journal(&self) -> &IntegrityJournal<D> {
        &self.journal
    }

    /// The copy catalog, read only.
    #[must_use]
    pub const fn copies(&self) -> &CopyCatalog<D> {
        &self.copies
    }

    /// The location of the local copy karyosd recorded when `recording`
    /// closed (karyos#1024): the earliest verified copy covering its whole
    /// closed extent with no retention. Read only; `None` when there is
    /// none.
    ///
    /// # Errors
    ///
    /// The copy catalog's error.
    pub fn recorded_location(&self, recording: &Recording) -> Result<Option<Digest>, OfflineError> {
        let Some(stop) = recording.stop.as_ref() else {
            return Ok(None);
        };
        Ok(self
            .copies
            .current()?
            .into_iter()
            .filter(|copy| {
                copy.recording == recording.id
                    && copy.retain_until_ns == 0
                    && copy.start <= recording.start
                    && copy.end >= stop.position
            })
            .min_by_key(|copy| copy.sequence)
            .map(|copy| copy.location))
    }

    /// Checks `location` against the location the Archive records for its
    /// own local copies ([`Offline::recorded_location`]).
    ///
    /// # Errors
    ///
    /// [`OfflineError::LocationMismatch`], [`OfflineError::NoLocalCopy`]
    /// or [`OfflineError::AmbiguousLocation`].
    pub fn check_location(&self, location: &Digest) -> Result<(), OfflineError> {
        let mut recorded = std::collections::BTreeSet::new();
        for recording in &self.recordings {
            if let Some(found) = self.recorded_location(recording)? {
                recorded.insert(found);
            }
        }
        let mut found = recorded.into_iter();
        match (found.next(), found.next()) {
            (None, _) => Err(OfflineError::NoLocalCopy),
            (Some(_), Some(_)) => Err(OfflineError::AmbiguousLocation),
            (Some(only), None) if only == *location => Ok(()),
            (Some(only), None) => Err(OfflineError::LocationMismatch {
                given: hex(location),
                recorded: hex(&only),
            }),
        }
    }

    fn recording(&self, id: u64) -> Result<Recording, OfflineError> {
        let recording = self
            .recordings
            .iter()
            .find(|recording| recording.id == id)
            .cloned()
            .ok_or(OfflineError::UnknownRecording(id))?;
        if recording.stop.is_none() {
            return Err(OfflineError::NotStopped(id));
        }
        Ok(recording)
    }

    /// Refuses while any purge intent of the Archive is unresolved, or
    /// while `recording` has a legal hold in any state (ADR-0104,
    /// decision 2).
    fn preconditions(&self, recording: u64) -> Result<(), OfflineError> {
        if let Some(intent) = self.retention.outstanding().first() {
            return Err(OfflineError::PurgeIntent {
                id: intent.id,
                recording: intent.recording,
            });
        }
        let state = match self.retention.hold_state(recording) {
            HoldState::None => return Ok(()),
            HoldState::Pending => "pending",
            HoldState::Held => "in force",
            _ => "unknown",
        };
        Err(OfflineError::LegalHold { recording, state })
    }

    /// `min_copies` and the retention deadline of `recording`: the
    /// policy's when one applies (its deadline counted from the close
    /// time), the option's with no deadline otherwise.
    fn terms(
        &self,
        recording: &Recording,
        options: &OffloadOptions,
    ) -> Result<(NonZeroU32, u64), OfflineError> {
        match self
            .book
            .resolve(recording.id, &recording.channel, recording.stream_id)
        {
            Some(policy) => {
                let closed = recording
                    .stop
                    .as_ref()
                    .and_then(|stop| stop.closed_utc_ns)
                    .unwrap_or(u64::MAX);
                Ok((
                    policy.min_copies,
                    closed.saturating_add(policy.retain_for_ns),
                ))
            }
            None => options
                .min_copies
                .map(|min| (min, 0))
                .ok_or(OfflineError::NoMinCopies(recording.id)),
        }
    }

    fn store(&self, recording: &Recording) -> Result<SegmentStore<D>, OfflineError> {
        Ok(SegmentStore::recover(
            self.disk.clone(),
            &self.dir,
            recording.id,
            recording.geometry,
            SyncPolicy::PerSegment,
        )?
        .store)
    }

    /// Offloads `recording`'s segments from its start, oldest first, to
    /// `store` (ADR-0104, decisions 1 to 4), after reconciling an offload
    /// or restore a crash cut short. It stops at the first segment that is
    /// not eligible, would fall below `min_copies`, or whose objects do
    /// not enforce the retention deadline, reporting why.
    ///
    /// # Errors
    ///
    /// The preconditions' refusals before anything is written, and the
    /// tiering, journal and store errors.
    pub fn offload<O: ObjectStore>(
        &mut self,
        tiering: &Tiering,
        id: u64,
        store: &mut O,
        options: &OffloadOptions,
    ) -> Result<OffloadReport, OfflineError> {
        let recording = self.recording(id)?;
        self.preconditions(id)?;
        let (min_copies, deadline) = self.terms(&recording, options)?;
        if !self.journal.tiered() && !options.accept_downgrade_break {
            return Err(OfflineError::DowngradeBreak);
        }
        let mut segments = self.store(&recording)?;
        tiering.reconcile(
            &mut self.copies,
            &mut self.journal,
            &mut segments,
            &mut Backend(self.immutability.as_mut()),
        )?;
        let mut report = OffloadReport {
            offloaded: Vec::new(),
            stopped: Stopped::NoneLeft,
        };
        loop {
            if options.limit.is_some_and(|limit| {
                u64::try_from(report.offloaded.len()).unwrap_or(u64::MAX) >= limit
            }) {
                report.stopped = Stopped::Limit;
                break;
            }
            let Some((start, end)) = segments.lowest_finished_segment() else {
                break;
            };
            let base = segments.geometry().base_of(start);
            let seals: Vec<SealRecord> = self
                .journal
                .records()?
                .into_iter()
                .filter(|record| {
                    record.kind.is_range()
                        && record.subject == id
                        && record.start < end
                        && record.end > start
                })
                .collect();
            let (data, index) = segments.segment_paths(base);
            let data = read_file(&mut self.disk, &data)?;
            let index = read_file(&mut self.disk, &index)?;
            let segment = LocalSegment {
                recording: id,
                base,
                start,
                end,
                seals: &seals,
                data: &data,
                index: &index,
            };
            let uploaded =
                match tiering.upload_segment(&segment, min_copies, deadline, &self.copies, store) {
                    Ok(uploaded) => uploaded,
                    Err(TieringError::NotEligible { base, why }) => {
                        report.stopped = Stopped::NotEligible { base, why };
                        break;
                    }
                    Err(TieringError::BelowMinCopies { verified, required }) => {
                        report.stopped = Stopped::BelowMinCopies {
                            base,
                            verified,
                            required,
                        };
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
            if deadline > 0
                && let Some(object) =
                    Self::unenforced(tiering, uploaded.ranges(), id, base, deadline, store)?
            {
                report.stopped = Stopped::LockNotEnforced { base, object };
                break;
            }
            let record = match tiering.commit_segment(
                &uploaded,
                min_copies,
                deadline,
                &mut self.copies,
                &mut self.journal,
                &mut segments,
                &mut Backend(self.immutability.as_mut()),
            ) {
                Ok(record) => record,
                // A commit refused before it records anything: the segment
                // stays local, reported.
                Err(TieringError::NotEligible { base, why }) => {
                    report.stopped = Stopped::NotEligible { base, why };
                    break;
                }
                Err(TieringError::BelowMinCopies { verified, required }) => {
                    report.stopped = Stopped::BelowMinCopies {
                        base,
                        verified,
                        required,
                    };
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            report.offloaded.push(record);
        }
        Ok(report)
    }

    /// The first object of an uploaded segment whose version read back
    /// does not enforce `deadline`: each range's and the index's.
    fn unenforced<O: ObjectStore>(
        tiering: &Tiering,
        ranges: &[(SealRecord, super::copies::Enforcement)],
        recording: u64,
        base: u64,
        deadline: u64,
        store: &mut O,
    ) -> Result<Option<String>, OfflineError> {
        let keys = ranges
            .iter()
            .map(|(seal, _)| ObjectKey::of(tiering.local, seal))
            .chain(std::iter::once(ObjectKey::index(
                tiering.local,
                recording,
                base,
            )));
        for key in keys {
            let enforced = store
                .retention(&key)
                .map_err(TieringError::Store)?
                .is_some_and(|retention| retention.enforces(deadline));
            if !enforced {
                return Ok(Some(key.name()));
            }
        }
        Ok(None)
    }

    /// Restores up to `limit` of `recording`'s offloaded segments from
    /// `store`, from the one just below the start downward, stopping at
    /// the offload floor (ADR-0104, decision 6), after reconciling a crash.
    /// Returns the restore records.
    ///
    /// # Errors
    ///
    /// The tiering, journal and store errors.
    pub fn restore<O: ObjectStore>(
        &mut self,
        tiering: &Tiering,
        id: u64,
        store: &mut O,
        limit: Option<u64>,
    ) -> Result<Vec<SealRecord>, OfflineError> {
        let recording = self.recording(id)?;
        let mut segments = self.store(&recording)?;
        tiering.reconcile(
            &mut self.copies,
            &mut self.journal,
            &mut segments,
            &mut Backend(self.immutability.as_mut()),
        )?;
        let mut restored = Vec::new();
        while segments.lowest_retained() < segments.start()
            && limit.is_none_or(|limit| u64::try_from(restored.len()).unwrap_or(u64::MAX) < limit)
        {
            restored.push(tiering.restore_segment(
                &mut self.copies,
                &mut self.journal,
                &mut segments,
                store,
            )?);
        }
        Ok(restored)
    }

    /// Verifies every object of `recording`'s offloaded segments in
    /// `store` (ADR-0104, decision 5): each range against its seal, each
    /// index against its recorded digest. A missing or corrupt range
    /// object downgrades the remote copy of its range in the copy catalog
    /// (removed or unverified).
    ///
    /// # Errors
    ///
    /// The journal's and the copy catalog's errors; object storage errors
    /// other than a missing object.
    pub fn verify<O: ObjectStore>(
        &mut self,
        tiering: &Tiering,
        id: u64,
        store: &mut O,
    ) -> Result<Vec<ObjectReport>, OfflineError> {
        let recording = self.recording(id)?;
        let records = self.journal.records()?;
        let offloads = offloaded(&records).remove(&id).unwrap_or_default();
        let mut reports = Vec::new();
        for offload in offloads {
            let base = recording.geometry.base_of(offload.start);
            let key = ObjectKey::index(tiering.local, id, base);
            let state = match store.get(&key) {
                Ok(bytes) if index_digest(&bytes) == offload.content => ObjectState::Verified,
                Ok(_) => ObjectState::Corrupt,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => ObjectState::Missing,
                Err(error) => return Err(TieringError::Store(error).into()),
            };
            reports.push(ObjectReport {
                object: key.name(),
                recording: id,
                start: base,
                end: base,
                state,
            });
            for seal in records.iter().filter(|record| {
                record.kind.is_range()
                    && record.subject == id
                    && record.start >= offload.start
                    && record.end <= offload.end
            }) {
                let key = ObjectKey::of(tiering.local, seal);
                let state = match store.get(&key) {
                    Ok(bytes) if verify_range(seal, &bytes).is_ok() => ObjectState::Verified,
                    Ok(_) => ObjectState::Corrupt,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        ObjectState::Missing
                    }
                    Err(error) => return Err(TieringError::Store(error).into()),
                };
                if state != ObjectState::Verified {
                    self.downgrade(tiering, seal, state)?;
                }
                reports.push(ObjectReport {
                    object: key.name(),
                    recording: id,
                    start: seal.start,
                    end: seal.end,
                    state,
                });
            }
        }
        Ok(reports)
    }

    /// Records the remote copy of `seal`'s range missing (removed) or
    /// corrupt (unverified): it stops counting.
    fn downgrade(
        &mut self,
        tiering: &Tiering,
        seal: &SealRecord,
        state: ObjectState,
    ) -> Result<(), OfflineError> {
        let counted: Vec<CopyRecord> = self
            .copies
            .current()?
            .into_iter()
            .filter(|copy| {
                copy.location == tiering.remote
                    && copy.recording == seal.subject
                    && copy.state == CopyState::Verified
                    && copy.start <= seal.start
                    && copy.end >= seal.end
            })
            .collect();
        let state = if state == ObjectState::Missing {
            CopyState::Removed
        } else {
            CopyState::Unverified
        };
        for copy in counted {
            self.copies
                .record(CopyRecord { state, ..copy }, &mut self.journal)?;
        }
        Ok(())
    }
}
