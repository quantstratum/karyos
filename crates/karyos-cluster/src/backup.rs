// SPDX-License-Identifier: Apache-2.0

//! Backups of a Cluster node's state to remote storage, and a rebuild from
//! one (quantstratum-docs: karyos/SPEC.md §9, "Snapshots and log segments
//! can be copied to remote storage under the retention rules of 8.4, and a
//! cluster can be rebuilt from them into an isolated environment for audit
//! or testing"; karyos#717).
//!
//! - **Export** ([`export`]) of a *stopped* node: its latest snapshot and
//!   its committed log after the snapshot's base go to remote storage
//!   through the Archive's [`ObjectStore`] (the S3 client implements it;
//!   nothing here depends on it), each retained until the caller's
//!   deadline ([`Retention`]); the report states the weakest enforcement
//!   the store gave ([`Report::retention`]), and an export that requires
//!   retention fails on the first object the store does not enforce it for
//!   ([`BackupError::RetentionNotEnforced`]). The snapshot's term is
//!   checked against the log's term at its base, and the commit must reach
//!   the base. Every object is read back and checked against the CRC-32C
//!   taken before the put before it counts, and the manifest goes last. An
//!   export refuses a remote that already holds an export of the cluster
//!   ([`BackupError::Exists`]): an export never overwrites another; a
//!   lookup that fails other than for a missing manifest fails the export
//!   before anything is put. The check is not atomic with the manifest's
//!   put: two exports of one cluster to one remote at once can interleave
//!   their objects, so the caller runs one at a time per remote (the
//!   `karyos-backup` tool holds a lock on its remote for that). Opening a
//!   node's stores runs their recovery, which can repair a torn tail: the
//!   caller exports from a copy of a stopped node's directories, never the
//!   node's own (the tool copies them first). It runs on the control path:
//!   nothing on the data path calls it.
//! - **Check** ([`verify`]): the manifest's structure (exactly one snapshot
//!   first, then log ranges covering the base's next index to the top in
//!   order, with no gap or overlap), then every object, one at a time: its
//!   CRC-32C and length, and its contents (every entry at the index its
//!   range says, terms never going down, the last the top).
//! - **Rebuild** ([`rebuild`]) into *empty* directories only: the export is
//!   checked whole first, as [`verify`] does, before anything is written;
//!   then each object is fetched again, rechecked and written, the
//!   snapshot streamed into the fresh store and published, the log
//!   restarted after its base and committed up to the top. A non-empty
//!   target is refused ([`BackupError::NotEmpty`]): a rebuild never
//!   installs over a node's state, so it never purges anything, and in
//!   particular nothing an Archive hold keeps (owner decisions 2026-10-21,
//!   item 35). A rebuild is not a unit: a failure after the checks (a disk
//!   error, or an object that changed or vanished between the check and its
//!   second read, [`BackupError::Damaged`] or remote storage's error) can
//!   leave the target partly written, a node that opens short of the top.
//!   Only a rebuild that returned its report is whole: anything else is
//!   discarded and the rebuild run again into empty directories. One
//!   rebuild runs per target at a time (the tool locks both directories).
//! - **Sections.** The check reads each snapshot section's framing; what a section's bytes must hold is the
//!   service's, checked by the hook [`verify_with`] and [`rebuild_with`]
//!   take, run on every section before anything is written. Without one,
//!   a snapshot whose service bytes the service cannot open passes.
//! - **Identity.** A rebuild writes its node's cluster identity last
//!   ([`crate::cluster_identity`], quantstratum-docs:
//!   karyos/adr/0123-cluster-identity.md, decision 2): a new one, derived
//!   from the export's identity, its top and the caller's random nonce,
//!   marked isolated from the source. A partly written target has none, so
//!   it does not start.
//! - **Report**: an export and a rebuild each report the index and term
//!   their state reaches and what they do not include ([`NOT_INCLUDED`]).
//!
//! The CRC-32C detects corruption; it claims no tamper evidence (item 15).
//! At most one object is held in memory at a time; an object is at most
//! [`ENTRIES_PER_OBJECT`] entries and [`MAX_OBJECT_BYTES`] bytes, but the
//! snapshot's object is as large as the snapshot.
//!
//! **Layout.** Objects are keyed by the cluster's 32-byte identity, as the
//! Archive keys an archive's: recording [`SNAPSHOT_OBJECT`] holds the
//! snapshot (one object, its sections framed as kind, version, length,
//! bytes), recording [`LOG_OBJECTS`] the log in ranges (`start` and `end`
//! are log indices, end exclusive), and recording [`MANIFEST_OBJECT`] the
//! manifest.

use std::io;
use std::path::Path;

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::Disk;
use karyos_archive::integrity::Digest;
use karyos_archive::integrity::copies::Enforcement;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectKind, ObjectStore};
use karyos_archive::segment::Geometry;

use crate::cluster_identity::{ClusterId, IdentityError, IdentityRecord, rebuild_identity};
use crate::log::{LogError, RaftLog};
use crate::snapshot::{SectionKind, SnapshotConfig, SnapshotError, SnapshotStore, WRITE_CHUNK};
use crate::{Entry, HardState};

/// The recording of the snapshot object.
pub const SNAPSHOT_OBJECT: u64 = 0;
/// The recording of the log's range objects.
pub const LOG_OBJECTS: u64 = 1;
/// The recording of the manifest object.
pub const MANIFEST_OBJECT: u64 = 2;
/// The most entries one log object holds.
pub const ENTRIES_PER_OBJECT: u64 = 1024;
/// The most bytes one log object holds, but for a single larger entry.
pub const MAX_OBJECT_BYTES: usize = 8 << 20;
/// The log bytes an export reads at once.
const READ_BYTES: u64 = 1 << 20;

/// What an export and a rebuild do not include, stated in every report.
pub const NOT_INCLUDED: &[&str] = &[
    "entries past the commit index (uncommitted entries are not exported)",
    "the node's term and vote (the rebuilt log takes the top entry's term, no vote)",
    "snapshots older than the latest",
    "the Archive's own recordings, holds and journals",
    "the source's cluster identity: the rebuild takes its own, derived from the source's and marked isolated, so the live cluster's peers and clients refuse it and it never enables external effects (ADR-0123)",
];

const MANIFEST_MAGIC: [u8; 4] = *b"KYBK";
const MANIFEST_VERSION: u32 = 1;
/// A log entry's fixed framing in an object: index, term, event time,
/// length.
const ENTRY_HEADER: usize = 32;

/// One object of an export, as its manifest lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listed {
    /// Its recording: [`SNAPSHOT_OBJECT`] or [`LOG_OBJECTS`].
    pub recording: u64,
    /// Its start: 0 for the snapshot, the first log index of a range.
    pub start: u64,
    /// Its end, exclusive: the snapshot's length, or the index after the
    /// range.
    pub end: u64,
    /// Its bytes.
    pub length: u64,
    /// Their CRC-32C.
    pub crc: u32,
}

/// An export's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The snapshot's base, as (index, term).
    pub base: (u64, u64),
    /// The last exported index and its term: the export's top.
    pub top: (u64, u64),
    /// Every object, the snapshot first, then the log ranges in order.
    pub objects: Vec<Listed>,
}

/// How long an export's objects are retained, and whether the store must
/// enforce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// The deadline, in nanoseconds since the epoch.
    pub until_ns: u64,
    /// Whether an object whose retention the store does not enforce fails
    /// the export.
    pub required: bool,
}

impl Retention {
    /// Retained until `until_ns`, as far as the store enforces it.
    #[must_use]
    pub const fn until(until_ns: u64) -> Self {
        Self {
            until_ns,
            required: false,
        }
    }

    /// The same, the store required to enforce it.
    #[must_use]
    pub const fn required(self) -> Self {
        Self {
            required: true,
            ..self
        }
    }
}

/// What an export or a rebuild reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The snapshot's base, as (index, term).
    pub base: (u64, u64),
    /// The top: the last index and its term.
    pub top: (u64, u64),
    /// The log entries after the base.
    pub entries: u64,
    /// The objects, the manifest included, each read back and checked.
    pub objects: u64,
    /// What it does not include.
    pub not_included: &'static [&'static str],
    /// An export's: the weakest retention the store enforced for its
    /// objects. A rebuild's: [`Enforcement::Unsupported`].
    pub retention: Enforcement,
    /// A rebuild's: the identity record it wrote. An export's: none.
    pub identity: Option<IdentityRecord>,
}

/// Why an export or a rebuild did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// The rebuild's identity record could not be written.
    #[error("the rebuild's cluster identity: {0}")]
    Identity(IdentityError),
    /// The node has no snapshot to export.
    #[error("the node has no snapshot to export")]
    NoSnapshot,
    /// The snapshot's term is not the log's at its base, or the log cannot
    /// tell: the snapshot is not this log's.
    #[error("the snapshot at {index} has term {snapshot}, the log {log:?}")]
    SnapshotTerm {
        /// The snapshot's base index.
        index: u64,
        /// Its term.
        snapshot: u64,
        /// The log's term there, if it holds one.
        log: Option<u64>,
    },
    /// The log's commit is below the snapshot's base, or unknown.
    #[error("the commit {commit:?} is below the snapshot's base {base}")]
    CommitBelowBase {
        /// The snapshot's base.
        base: u64,
        /// The stored commit.
        commit: Option<u64>,
    },
    /// The log does not hold every committed entry after the snapshot's
    /// base.
    #[error("the log does not hold the committed entries after {base}")]
    LogShort {
        /// The snapshot's base.
        base: u64,
    },
    /// Retention was required, and the store did not enforce it for an
    /// object: its enforcement.
    #[error("the store does not enforce the required retention: {0:?}")]
    RetentionNotEnforced(Enforcement),
    /// A snapshot section the check refused: its kind, and why.
    #[error("the snapshot's {kind:?} section is refused: {reason}")]
    Section {
        /// Its kind.
        kind: SectionKind,
        /// Why.
        reason: String,
    },
    /// The remote already holds an export of the cluster: an export never
    /// overwrites another.
    #[error("the remote already holds an export of this cluster")]
    Exists,
    /// An object's bytes do not match its manifest entry or its range, or
    /// did not read back whole after an export's put: its recording and
    /// range.
    #[error("object {recording} {start}..{end} is damaged")]
    Damaged {
        /// Its recording.
        recording: u64,
        /// Its start.
        start: u64,
        /// Its end, exclusive.
        end: u64,
    },
    /// The manifest is missing, damaged, or does not describe a whole
    /// export: why.
    #[error("the export's manifest is missing or invalid: {0}")]
    Manifest(&'static str),
    /// A rebuild's target directories are not empty, or cannot be listed.
    #[error("the rebuild's target {0} is not empty")]
    NotEmpty(String),
    /// The snapshot store's error.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    /// The log's error.
    #[error(transparent)]
    Log(#[from] LogError),
    /// Remote storage's error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn key(cluster: Digest, recording: u64, start: u64, end: u64) -> ObjectKey {
    ObjectKey {
        archive: cluster,
        recording,
        start,
        end,
        kind: if recording == MANIFEST_OBJECT {
            ObjectKind::Index
        } else {
            ObjectKind::Range
        },
    }
}

fn damaged(listed: &Listed) -> BackupError {
    BackupError::Damaged {
        recording: listed.recording,
        start: listed.start,
        end: listed.end,
    }
}

/// Puts `bytes` under `listed`'s key, reads them back and checks them.
fn put_checked(
    store: &mut impl ObjectStore,
    cluster: Digest,
    listed: &Listed,
    bytes: &[u8],
    retention: Retention,
) -> Result<Enforcement, BackupError> {
    let key = key(cluster, listed.recording, listed.start, listed.end);
    let enforced = store.put(&key, bytes, retention.until_ns)?;
    if retention.required && enforced == Enforcement::Unsupported {
        return Err(BackupError::RetentionNotEnforced(enforced));
    }
    let back = store.get(&key)?;
    if back.len() as u64 != listed.length || crc32c(&back) != listed.crc {
        return Err(damaged(listed));
    }
    Ok(enforced)
}

/// The weaker of two enforcements.
const fn weaker(a: Enforcement, b: Enforcement) -> Enforcement {
    if (a as u8) <= (b as u8) { a } else { b }
}

/// Whether the export's manifest under `cluster` is there: a missing one is
/// `false`; any other failure to look is the store's error.
fn has_manifest(store: &mut impl ObjectStore, cluster: Digest) -> Result<bool, BackupError> {
    match store.get(&key(cluster, MANIFEST_OBJECT, 0, 0)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(BackupError::Io(error)),
    }
}

/// Exports a stopped node's latest snapshot and its committed log after it
/// to `store` under `cluster`, retained as `retention` says. The stores are
/// a copy of the node's directories: opening them runs their recovery.
///
/// # Errors
///
/// [`BackupError::Exists`] for a remote that holds an export of `cluster`;
/// [`BackupError::NoSnapshot`], [`BackupError::SnapshotTerm`],
/// [`BackupError::CommitBelowBase`] and [`BackupError::LogShort`], before
/// anything is put; [`BackupError::Damaged`] for a copy that does not read
/// back whole; [`BackupError::RetentionNotEnforced`] when retention is
/// required and the store does not enforce it; the stores' errors, a
/// failed manifest lookup among them. An export that fails before its
/// manifest's put has no manifest; one whose manifest's read-back fails may
/// have one, which [`verify`] then judges.
pub fn export<D: Disk + Clone, E: Disk + Clone>(
    snapshots: &SnapshotStore<E>,
    log: &mut RaftLog<D>,
    store: &mut impl ObjectStore,
    cluster: Digest,
    retention: Retention,
) -> Result<Report, BackupError> {
    if has_manifest(store, cluster)? {
        return Err(BackupError::Exists);
    }
    let info = snapshots.latest().ok_or(BackupError::NoSnapshot)?;
    let base = info.index;
    // The snapshot must be this log's: its term is the log's at its base,
    // as the log holds it or as an install recorded it.
    let log_term = log.term(base).or_else(|| {
        log.base()
            .filter(|(index, _)| *index == base)
            .map(|(_, term)| term)
    });
    if base > 0 && log_term != Some(info.term) {
        return Err(BackupError::SnapshotTerm {
            index: base,
            snapshot: info.term,
            log: log_term,
        });
    }
    let commit = log.hard_state().and_then(|state| state.commit);
    let commit = match commit {
        Some(commit) if commit >= base => commit,
        commit => return Err(BackupError::CommitBelowBase { base, commit }),
    };
    // The snapshot, framed section by section.
    let mut reader = snapshots.reader(&info)?;
    let mut bytes = Vec::new();
    let mut buf = vec![0u8; WRITE_CHUNK];
    while let Some(header) = reader.next_section()? {
        bytes.extend_from_slice(&header.kind.code().to_le_bytes());
        bytes.extend_from_slice(&header.version.to_le_bytes());
        bytes.extend_from_slice(&header.length.to_le_bytes());
        loop {
            let read = reader.read(&mut buf)?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(buf.get(..read).unwrap_or(&[]));
        }
    }
    let snapshot = Listed {
        recording: SNAPSHOT_OBJECT,
        start: 0,
        end: bytes.len() as u64,
        length: bytes.len() as u64,
        crc: crc32c(&bytes),
    };
    let mut enforced = put_checked(store, cluster, &snapshot, &bytes, retention)?;
    drop(bytes);
    let mut objects = vec![snapshot];
    // The committed log after the base, in ranges bounded in entries and
    // bytes.
    let mut top = (info.index, info.term);
    let mut next = base + 1;
    let mut entries = 0u64;
    while next <= commit {
        let limit = (next + ENTRIES_PER_OBJECT).min(commit + 1);
        let mut chunk = Vec::new();
        let mut at = next;
        while at < limit && (chunk.is_empty() || chunk.len() < MAX_OBJECT_BYTES) {
            let budget = (MAX_OBJECT_BYTES - chunk.len()) as u64;
            let read = log.entries(at..limit, budget.min(READ_BYTES))?;
            if read.is_empty() {
                return Err(BackupError::LogShort { base });
            }
            for entry in &read {
                chunk.extend_from_slice(&entry.index.to_le_bytes());
                chunk.extend_from_slice(&entry.term.to_le_bytes());
                chunk.extend_from_slice(&entry.event_time.to_le_bytes());
                chunk.extend_from_slice(&(entry.payload.len() as u64).to_le_bytes());
                chunk.extend_from_slice(&entry.payload);
                top = (entry.index, entry.term);
                entries += 1;
            }
            at += read.len() as u64;
        }
        let listed = Listed {
            recording: LOG_OBJECTS,
            start: next,
            end: at,
            length: chunk.len() as u64,
            crc: crc32c(&chunk),
        };
        enforced = weaker(
            enforced,
            put_checked(store, cluster, &listed, &chunk, retention)?,
        );
        objects.push(listed);
        next = at;
    }
    let manifest = Manifest {
        base: (info.index, info.term),
        top,
        objects,
    };
    manifest.validate()?;
    let encoded = manifest.encode();
    let listed = Listed {
        recording: MANIFEST_OBJECT,
        start: 0,
        end: 0,
        length: encoded.len() as u64,
        crc: crc32c(&encoded),
    };
    // Looked for again: an export that started since is caught here, but
    // the caller still runs one at a time.
    if has_manifest(store, cluster)? {
        return Err(BackupError::Exists);
    }
    enforced = weaker(
        enforced,
        put_checked(store, cluster, &listed, &encoded, retention)?,
    );
    Ok(Report {
        base: manifest.base,
        top,
        entries,
        objects: manifest.objects.len() as u64 + 1,
        not_included: NOT_INCLUDED,
        retention: enforced,
        identity: None,
    })
}

impl Manifest {
    /// Its bytes: magic, version, base, top, the objects, and the CRC-32C
    /// of all before it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MANIFEST_MAGIC);
        bytes.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        for value in [self.base.0, self.base.1, self.top.0, self.top.1] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.objects.len() as u64).to_le_bytes());
        for object in &self.objects {
            for value in [object.recording, object.start, object.end, object.length] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&object.crc.to_le_bytes());
        }
        let crc = crc32c(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes
    }

    /// The manifest `bytes` hold, whole and checked.
    ///
    /// # Errors
    ///
    /// [`BackupError::Manifest`] for anything else.
    pub fn decode(bytes: &[u8]) -> Result<Self, BackupError> {
        let bad = BackupError::Manifest("its bytes do not decode whole");
        let (body, crc) = bytes
            .split_at_checked(bytes.len().saturating_sub(4))
            .ok_or(BackupError::Manifest("too short"))?;
        let stored = <[u8; 4]>::try_from(crc).map(u32::from_le_bytes).ok();
        if stored != Some(crc32c(body)) {
            return Err(BackupError::Manifest("its CRC-32C does not match"));
        }
        let mut cursor = Cursor(body);
        let header = (|| Some((cursor.take(4)?.to_vec(), cursor.u32()?)))();
        if header != Some((MANIFEST_MAGIC.to_vec(), MANIFEST_VERSION)) {
            return Err(bad);
        }
        let numbers = (|| {
            let base = (cursor.u64()?, cursor.u64()?);
            let top = (cursor.u64()?, cursor.u64()?);
            let count = cursor.u64()?;
            let mut objects = Vec::new();
            for _ in 0..count {
                objects.push(Listed {
                    recording: cursor.u64()?,
                    start: cursor.u64()?,
                    end: cursor.u64()?,
                    length: cursor.u64()?,
                    crc: cursor.u32()?,
                });
            }
            Some((base, top, objects))
        })();
        let Some((base, top, objects)) = numbers else {
            return Err(bad);
        };
        if !cursor.0.is_empty() {
            return Err(bad);
        }
        Ok(Self { base, top, objects })
    }

    /// Checks that the manifest describes a whole export: exactly one
    /// snapshot, first; then log ranges in order covering the base's next
    /// index to the top, each non-empty and at most
    /// [`ENTRIES_PER_OBJECT`] entries, with no gap or overlap; a top at the
    /// base exactly when there is none.
    ///
    /// # Errors
    ///
    /// [`BackupError::Manifest`], with what is wrong.
    pub fn validate(&self) -> Result<(), BackupError> {
        let Some((snapshot, ranges)) = self.objects.split_first() else {
            return Err(BackupError::Manifest("no object"));
        };
        if snapshot.recording != SNAPSHOT_OBJECT
            || snapshot.start != 0
            || snapshot.end != snapshot.length
        {
            return Err(BackupError::Manifest(
                "the first object is not the snapshot",
            ));
        }
        if self.top.0 < self.base.0 || self.top.1 < self.base.1 {
            return Err(BackupError::Manifest("the top is below the base"));
        }
        let mut next = self
            .base
            .0
            .checked_add(1)
            .ok_or(BackupError::Manifest("the base overflows"))?;
        for range in ranges {
            if range.recording != LOG_OBJECTS {
                return Err(BackupError::Manifest(
                    "an object after the first is not a log range",
                ));
            }
            if range.start != next
                || range.end <= range.start
                || range.end - range.start > ENTRIES_PER_OBJECT
            {
                return Err(BackupError::Manifest(
                    "the log ranges leave a gap, overlap or are empty",
                ));
            }
            next = range.end;
        }
        let covered = next - 1;
        if covered != self.top.0 {
            return Err(BackupError::Manifest(
                "the log ranges do not end at the top",
            ));
        }
        Ok(())
    }
}

/// A reader over manifest or object bytes.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

/// A snapshot object's sections, as (kind, version, bytes).
fn snapshot_sections(bytes: &[u8]) -> Option<Vec<(SectionKind, u64, &[u8])>> {
    let mut cursor = Cursor(bytes);
    let mut sections = Vec::new();
    while !cursor.0.is_empty() {
        let kind = SectionKind::from_code(cursor.u32()?)?;
        let version = cursor.u64()?;
        let length = usize::try_from(cursor.u64()?).ok()?;
        sections.push((kind, version, cursor.take(length)?));
    }
    (!sections.is_empty()).then_some(sections)
}

/// A log object's entries, each at the index its range says, terms never
/// below `floor` nor going down.
fn log_entries(bytes: &[u8], listed: &Listed, floor: u64) -> Option<Vec<Entry>> {
    let mut cursor = Cursor(bytes);
    let mut entries = Vec::new();
    let mut expected = listed.start;
    let mut term_floor = floor;
    while !cursor.0.is_empty() {
        if cursor.0.len() < ENTRY_HEADER {
            return None;
        }
        let index = cursor.u64()?;
        let term = cursor.u64()?;
        let event_time = cursor.u64()?;
        let length = usize::try_from(cursor.u64()?).ok()?;
        let payload = cursor.take(length)?.to_vec();
        if index != expected || term < term_floor {
            return None;
        }
        expected += 1;
        term_floor = term;
        entries.push(Entry {
            index,
            term,
            event_time,
            payload,
        });
    }
    (expected == listed.end).then_some(entries)
}

/// Fetches `listed` and checks its length and CRC-32C.
fn fetch(
    store: &mut impl ObjectStore,
    cluster: Digest,
    listed: &Listed,
) -> Result<Vec<u8>, BackupError> {
    let bytes = store
        .get(&key(cluster, listed.recording, listed.start, listed.end))
        .map_err(|_| damaged(listed))?;
    if bytes.len() as u64 != listed.length || crc32c(&bytes) != listed.crc {
        return Err(damaged(listed));
    }
    Ok(bytes)
}

/// The export's manifest under `cluster`, decoded and validated.
///
/// # Errors
///
/// [`BackupError::Manifest`] when it is missing, damaged or invalid;
/// remote storage's error when it cannot be looked for.
pub fn manifest(store: &mut impl ObjectStore, cluster: Digest) -> Result<Manifest, BackupError> {
    let bytes = store
        .get(&key(cluster, MANIFEST_OBJECT, 0, 0))
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => BackupError::Manifest("missing"),
            _ => BackupError::Io(error),
        })?;
    let manifest = Manifest::decode(&bytes)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Checks every object of the export under `cluster`, one at a time,
/// changing nothing: its bytes against the manifest, and its contents
/// against its range; the last entry is the top. What an auditor runs
/// before trusting a copy, and what [`rebuild`] runs before writing.
///
/// # Errors
///
/// [`BackupError::Manifest`] and [`BackupError::Damaged`], naming the
/// first damaged object.
pub fn verify(store: &mut impl ObjectStore, cluster: Digest) -> Result<Manifest, BackupError> {
    verify_with(store, cluster, &mut |_, _, _| Ok(()))
}

/// A check of one snapshot section: its kind, version and bytes; why it is
/// refused, if it is.
pub type SectionCheck<'a> = dyn FnMut(SectionKind, u64, &[u8]) -> Result<(), String> + 'a;

/// Checks each snapshot section, through `check`.
fn check_sections(
    sections: &[(SectionKind, u64, &[u8])],
    check: &mut SectionCheck<'_>,
) -> Result<(), BackupError> {
    for (kind, version, body) in sections {
        check(*kind, *version, body).map_err(|reason| BackupError::Section {
            kind: *kind,
            reason,
        })?;
    }
    Ok(())
}

/// [`verify`], each snapshot section also run through `check`: what the
/// service its snapshot restores requires of its bytes.
///
/// # Errors
///
/// As [`verify`], and [`BackupError::Section`] for a section `check`
/// refuses.
pub fn verify_with(
    store: &mut impl ObjectStore,
    cluster: Digest,
    check: &mut SectionCheck<'_>,
) -> Result<Manifest, BackupError> {
    let manifest = manifest(store, cluster)?;
    let mut floor = manifest.base.1;
    let mut last = manifest.base;
    for listed in &manifest.objects {
        let bytes = fetch(store, cluster, listed)?;
        if listed.recording == SNAPSHOT_OBJECT {
            let sections = snapshot_sections(&bytes).ok_or_else(|| damaged(listed))?;
            check_sections(&sections, check)?;
        } else {
            let entries = log_entries(&bytes, listed, floor).ok_or_else(|| damaged(listed))?;
            if let Some(entry) = entries.last() {
                floor = entry.term;
                last = (entry.index, entry.term);
            }
        }
    }
    if last != manifest.top {
        return Err(BackupError::Manifest("the last entry is not the top"));
    }
    Ok(manifest)
}

/// Where a rebuild writes: a node's log and snapshot directories on `disk`,
/// both existing and empty.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a, D> {
    /// The disk.
    pub disk: &'a D,
    /// The log's directory.
    pub log: &'a Path,
    /// The snapshot store's directory.
    pub snapshots: &'a Path,
    /// Their geometry.
    pub geometry: Geometry,
    /// The rebuild identity's random nonce, drawn by the caller from the
    /// operating system (ADR-0123 decision 2).
    pub nonce: [u8; 32],
}

/// Rebuilds a node from the export under `cluster` into `target`, whose
/// directories are empty: the export is checked whole first ([`verify`]),
/// then each object is fetched again, rechecked and written, the snapshot
/// streamed into a fresh store and published and the log restarted after
/// its base, committed up to the top.
///
/// # Errors
///
/// [`BackupError::NotEmpty`], [`BackupError::Manifest`] and
/// [`BackupError::Damaged`], before anything is written. After, the
/// stores' errors, or [`BackupError::Damaged`] for an object that changed
/// since its check, leave the target partly written: a node that may open
/// short of the top, to be discarded.
pub fn rebuild<D: Disk + Clone>(
    store: &mut impl ObjectStore,
    cluster: Digest,
    target: &Target<'_, D>,
) -> Result<Report, BackupError> {
    rebuild_with(store, cluster, target, &mut |_, _, _| Ok(()))
}

/// [`rebuild`], each snapshot section run through `check` (as
/// [`verify_with`]) before anything is written, and again before it is.
///
/// # Errors
///
/// As [`rebuild`], and [`BackupError::Section`] for a section `check`
/// refuses.
pub fn rebuild_with<D: Disk + Clone>(
    store: &mut impl ObjectStore,
    cluster: Digest,
    target: &Target<'_, D>,
    check: &mut SectionCheck<'_>,
) -> Result<Report, BackupError> {
    for dir in [target.log, target.snapshots] {
        let names = target
            .disk
            .clone()
            .list(dir)
            .map_err(|_| BackupError::NotEmpty(dir.display().to_string()))?;
        if !names.is_empty() {
            return Err(BackupError::NotEmpty(dir.display().to_string()));
        }
    }
    let manifest = verify_with(store, cluster, check)?;
    let (base, base_term) = manifest.base;
    let mut snapshots = SnapshotStore::open(
        target.disk.clone(),
        target.snapshots,
        target.geometry,
        SnapshotConfig::default(),
    )?
    .store;
    let mut log = RaftLog::create(target.disk.clone(), target.log, target.geometry, 1)?;
    let mut entries = 0u64;
    let mut floor = base_term;
    for listed in &manifest.objects {
        // Fetched again and rechecked: what is written is what was checked.
        let bytes = fetch(store, cluster, listed)?;
        if listed.recording == SNAPSHOT_OBJECT {
            let sections = snapshot_sections(&bytes).ok_or_else(|| damaged(listed))?;
            check_sections(&sections, check)?;
            let mut pending = snapshots.begin(base, base_term)?;
            for (kind, version, body) in sections {
                pending.section(kind, version, body.len() as u64)?;
                for piece in body.chunks(WRITE_CHUNK) {
                    pending.write(piece)?;
                }
            }
            let _ = snapshots.publish(pending)?;
            log.install(base, base_term, &snapshots)?;
            continue;
        }
        let batch = log_entries(&bytes, listed, floor).ok_or_else(|| damaged(listed))?;
        if let Some(entry) = batch.last() {
            floor = entry.term;
        }
        entries += batch.len() as u64;
        let _ = log.append(&batch)?;
    }
    let _ = log.sync()?;
    log.save_hard_state(HardState {
        current_term: manifest.top.1,
        voted_for: None,
        commit: Some(manifest.top.0),
    })?;
    let identity = IdentityRecord {
        identity: rebuild_identity(
            ClusterId(cluster),
            manifest.top.0,
            manifest.top.1,
            target.nonce,
        ),
        isolated_from: Some(ClusterId(cluster)),
    };
    identity
        .create(&mut target.disk.clone(), target.log)
        .map_err(BackupError::Identity)?;
    Ok(Report {
        identity: Some(identity),
        base: manifest.base,
        top: manifest.top,
        entries,
        objects: manifest.objects.len() as u64 + 1,
        not_included: NOT_INCLUDED,
        retention: Enforcement::Unsupported,
    })
}
