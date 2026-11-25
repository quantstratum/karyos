// SPDX-License-Identifier: Apache-2.0

//! Backups of a Cluster node's state to remote storage, and a rebuild from
//! one (quantstratum-docs: karyos/SPEC.md §9, "Snapshots and log segments
//! can be copied to remote storage under the retention rules of 8.4, and a
//! cluster can be rebuilt from them into an isolated environment for audit
//! or testing"; karyos#717).
//!
//! - **Export** ([`export`]): the node's latest snapshot and its committed
//!   log after the snapshot's base go to remote storage through the
//!   Archive's [`ObjectStore`] (the S3 client implements it; nothing here
//!   depends on it), each retained until the caller's deadline. Every
//!   object is read back and checked against the CRC-32C taken before the
//!   put before it counts: an export whose copy does not read back whole
//!   is refused, and nothing counts it. The manifest goes last, so an
//!   export a failure cut short has no manifest and is never rebuilt
//!   from. It reads the snapshot store and the log only, on the control
//!   path: nothing on the data path calls it.
//! - **Rebuild** ([`rebuild`]): from an export's manifest, the snapshot is
//!   streamed into a fresh snapshot store piece by piece and published,
//!   and the log restarts after its base with the exported entries,
//!   committed up to the export's top. Every object is checked against
//!   the manifest's CRC-32C before anything is written: a damaged one is
//!   refused, naming its range ([`BackupError::Damaged`]). A target that
//!   already holds a log is installed over only under the Archive's hold
//!   ([`HoldSource`]): through a hold it is refused, typed, and nothing
//!   changes (owner decisions 2026-10-21, item 35).
//! - **Report**: an export and a rebuild each report the index and term
//!   their state reaches and what they do not include ([`NOT_INCLUDED`]).
//!
//! The CRC-32C detects corruption; it claims no tamper evidence (item 15).
//!
//! **Layout.** Objects are keyed by the cluster's 32-byte identity, as the
//! Archive keys an archive's: recording [`SNAPSHOT_OBJECT`] holds the
//! snapshot (one object, its sections framed as kind, version, length,
//! bytes), recording [`LOG_OBJECTS`] the log in ranges of at most
//! [`ENTRIES_PER_OBJECT`] entries (`start` and `end` are log indices, end
//! exclusive), and recording [`MANIFEST_OBJECT`] the manifest.

use std::io;
use std::path::Path;

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::Disk;
use karyos_archive::integrity::Digest;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectKind, ObjectStore};
use karyos_archive::segment::Geometry;

use crate::log::{HoldSource, LogError, RaftLog};
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
/// The log bytes an export or a rebuild reads at once.
const READ_BYTES: u64 = 1 << 20;

/// What an export and a rebuild do not include, stated in every report.
pub const NOT_INCLUDED: &[&str] = &[
    "entries past the commit index (uncommitted entries are not exported)",
    "the node's term and vote (the rebuilt log takes the top entry's term, no vote)",
    "snapshots older than the latest",
    "the Archive's own recordings, holds and journals",
    "the live cluster's membership and identity: a rebuild is its own cluster",
];

const MANIFEST_MAGIC: [u8; 4] = *b"KYBK";
const MANIFEST_VERSION: u32 = 1;

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

/// What an export or a rebuild reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The snapshot's base, as (index, term).
    pub base: (u64, u64),
    /// The top: the last index and its term.
    pub top: (u64, u64),
    /// The log entries after the base.
    pub entries: u64,
    /// The objects, each read back and checked.
    pub objects: u64,
    /// What it does not include.
    pub not_included: &'static [&'static str],
}

/// Why an export or a rebuild did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// The node has no snapshot to export.
    #[error("the node has no snapshot to export")]
    NoSnapshot,
    /// The log does not hold every committed entry after the snapshot's
    /// base, or not its base's term.
    #[error("the log does not hold the committed entries after {base}")]
    LogShort {
        /// The snapshot's base.
        base: u64,
    },
    /// An object's bytes do not match its manifest entry, or did not read
    /// back whole after an export's put: its recording and range.
    #[error("object {recording} {start}..{end} is damaged")]
    Damaged {
        /// Its recording.
        recording: u64,
        /// Its start.
        start: u64,
        /// Its end, exclusive.
        end: u64,
    },
    /// The manifest is missing or does not decode whole.
    #[error("the export's manifest is missing or damaged")]
    Manifest,
    /// The snapshot store's error.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    /// The log's error: [`LogError::ArchiveHeld`] for a rebuild through a
    /// hold.
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

/// Puts `bytes` under `listed`'s key, reads them back and checks them.
fn put_checked(
    store: &mut impl ObjectStore,
    cluster: Digest,
    listed: &Listed,
    bytes: &[u8],
    retain_until_ns: u64,
) -> Result<(), BackupError> {
    let key = key(cluster, listed.recording, listed.start, listed.end);
    let _ = store.put(&key, bytes, retain_until_ns)?;
    let back = store.get(&key)?;
    if back.len() as u64 != listed.length || crc32c(&back) != listed.crc {
        return Err(BackupError::Damaged {
            recording: listed.recording,
            start: listed.start,
            end: listed.end,
        });
    }
    Ok(())
}

/// Exports the node's latest snapshot and its committed log after it to
/// `store` under `cluster`, retained until `retain_until_ns`; every object
/// is read back and checked, the manifest last.
///
/// # Errors
///
/// [`BackupError::NoSnapshot`], [`BackupError::LogShort`],
/// [`BackupError::Damaged`] for a copy that does not read back whole, and
/// the stores' errors. An export that fails has no manifest.
pub fn export<D: Disk + Clone, E: Disk + Clone>(
    snapshots: &SnapshotStore<E>,
    log: &mut RaftLog<D>,
    store: &mut impl ObjectStore,
    cluster: Digest,
    retain_until_ns: u64,
) -> Result<Report, BackupError> {
    let info = snapshots.latest().ok_or(BackupError::NoSnapshot)?;
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
    put_checked(store, cluster, &snapshot, &bytes, retain_until_ns)?;
    let mut objects = vec![snapshot];
    // The committed log after the base, in ranges.
    let base = info.index;
    let commit = log
        .hard_state()
        .and_then(|state| state.commit)
        .unwrap_or(base)
        .max(base);
    let mut top = (info.index, info.term);
    let mut next = base + 1;
    let mut entries = 0u64;
    while next <= commit {
        let end = (next + ENTRIES_PER_OBJECT).min(commit + 1);
        let mut chunk = Vec::new();
        let mut at = next;
        while at < end {
            let read = log.entries(at..end, READ_BYTES)?;
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
            end,
            length: chunk.len() as u64,
            crc: crc32c(&chunk),
        };
        put_checked(store, cluster, &listed, &chunk, retain_until_ns)?;
        objects.push(listed);
        next = end;
    }
    let manifest = Manifest {
        base: (info.index, info.term),
        top,
        objects,
    };
    let encoded = manifest.encode();
    let listed = Listed {
        recording: MANIFEST_OBJECT,
        start: 0,
        end: 0,
        length: encoded.len() as u64,
        crc: crc32c(&encoded),
    };
    put_checked(store, cluster, &listed, &encoded, retain_until_ns)?;
    Ok(Report {
        base: manifest.base,
        top,
        entries,
        objects: manifest.objects.len() as u64 + 1,
        not_included: NOT_INCLUDED,
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
        let (body, crc) = bytes
            .split_at_checked(bytes.len().saturating_sub(4))
            .ok_or(BackupError::Manifest)?;
        if u32::from_le_bytes(crc.try_into().map_err(|_| BackupError::Manifest)?) != crc32c(body) {
            return Err(BackupError::Manifest);
        }
        let mut cursor = Cursor(body);
        if cursor.take(4)? != MANIFEST_MAGIC || cursor.u32()? != MANIFEST_VERSION {
            return Err(BackupError::Manifest);
        }
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
        if !cursor.0.is_empty() {
            return Err(BackupError::Manifest);
        }
        Ok(Self { base, top, objects })
    }
}

/// A reader over manifest or object bytes.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], BackupError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(BackupError::Manifest)?;
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, BackupError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| BackupError::Manifest)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, BackupError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| BackupError::Manifest)?,
        ))
    }
}

/// Fetches `listed` from `store` and checks it against the manifest.
fn fetch(
    store: &mut impl ObjectStore,
    cluster: Digest,
    listed: &Listed,
) -> Result<Vec<u8>, BackupError> {
    let damaged = || BackupError::Damaged {
        recording: listed.recording,
        start: listed.start,
        end: listed.end,
    };
    let bytes = store
        .get(&key(cluster, listed.recording, listed.start, listed.end))
        .map_err(|_| damaged())?;
    if bytes.len() as u64 != listed.length || crc32c(&bytes) != listed.crc {
        return Err(damaged());
    }
    Ok(bytes)
}

/// The export's manifest under `cluster`.
///
/// # Errors
///
/// [`BackupError::Manifest`] when it is missing or damaged.
pub fn manifest(store: &mut impl ObjectStore, cluster: Digest) -> Result<Manifest, BackupError> {
    let bytes = store
        .get(&key(cluster, MANIFEST_OBJECT, 0, 0))
        .map_err(|_| BackupError::Manifest)?;
    Manifest::decode(&bytes)
}

/// Checks every object of the export under `cluster` against its manifest,
/// changing nothing: what an auditor runs before trusting a rebuild.
///
/// # Errors
///
/// [`BackupError::Manifest`] and [`BackupError::Damaged`], naming the
/// first damaged object.
pub fn verify(store: &mut impl ObjectStore, cluster: Digest) -> Result<Manifest, BackupError> {
    let manifest = manifest(store, cluster)?;
    for listed in &manifest.objects {
        let _ = fetch(store, cluster, listed)?;
    }
    Ok(manifest)
}

/// Where a rebuild writes: a node's log and snapshot directories on `disk`,
/// which exist; an empty log directory makes a fresh node.
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
}

/// Rebuilds a node from the export under `cluster` into `target`: the
/// export is checked whole first, then the snapshot is streamed into the
/// target's snapshot store and published, and the log restarts after its
/// base with the exported entries, committed up to the top. A target that
/// already holds a log is installed over only when `hold` holds nothing.
///
/// # Errors
///
/// [`BackupError::Manifest`] and [`BackupError::Damaged`], before anything
/// is written; [`BackupError::Log`] with [`LogError::ArchiveHeld`] through
/// a hold, changing nothing; the stores' errors.
pub fn rebuild<D: Disk + Clone>(
    store: &mut impl ObjectStore,
    cluster: Digest,
    target: &Target<'_, D>,
    hold: &impl HoldSource,
) -> Result<Report, BackupError> {
    // Everything checked before anything is written.
    let manifest = manifest(store, cluster)?;
    let mut fetched = Vec::with_capacity(manifest.objects.len());
    for listed in &manifest.objects {
        fetched.push((*listed, fetch(store, cluster, listed)?));
    }
    let (base, base_term) = manifest.base;
    // A target that holds a log is opened, and refused through a hold
    // before anything changes.
    let existing = target
        .disk
        .clone()
        .list(target.log)
        .map(|names| !names.is_empty())
        .unwrap_or(false);
    // Over a node's log, the hold is read before anything is opened: an
    // open may rewrite the log's watermark, and nothing may change through
    // a hold.
    if existing {
        match hold.hold_state() {
            karyos_archive::control::HoldState::None => {}
            state => return Err(BackupError::Log(LogError::ArchiveHeld { state })),
        }
    }
    let mut snapshots = SnapshotStore::open(
        target.disk.clone(),
        target.snapshots,
        target.geometry,
        SnapshotConfig::default(),
    )?
    .store;
    let mut log = if existing {
        RaftLog::open_with_under(
            target.disk.clone(),
            target.log,
            target.geometry,
            Some(&snapshots),
            hold,
        )?
        .log
    } else {
        RaftLog::create(target.disk.clone(), target.log, target.geometry, 1)?
    };
    // The snapshot, streamed into the target's store.
    let mut entries = 0u64;
    for (listed, bytes) in &fetched {
        if listed.recording != SNAPSHOT_OBJECT {
            continue;
        }
        let mut pending = snapshots.begin(base, base_term)?;
        let mut cursor = Cursor(bytes);
        while !cursor.0.is_empty() {
            let damaged = |_| BackupError::Damaged {
                recording: listed.recording,
                start: listed.start,
                end: listed.end,
            };
            let code = cursor.u32().map_err(damaged)?;
            let version = cursor.u64().map_err(damaged)?;
            let length = cursor.u64().map_err(damaged)?;
            let kind = SectionKind::from_code(code).ok_or(BackupError::Damaged {
                recording: listed.recording,
                start: listed.start,
                end: listed.end,
            })?;
            pending.section(kind, version, length)?;
            let body = cursor
                .take(usize::try_from(length).unwrap_or(usize::MAX))
                .map_err(damaged)?;
            for piece in body.chunks(WRITE_CHUNK) {
                pending.write(piece)?;
            }
        }
        let _ = snapshots.publish(pending)?;
    }
    log.install_under(base, base_term, &snapshots, hold)?;
    // The log after the base, in order.
    let mut top = manifest.base;
    for (listed, bytes) in &fetched {
        if listed.recording != LOG_OBJECTS {
            continue;
        }
        let damaged = |_| BackupError::Damaged {
            recording: listed.recording,
            start: listed.start,
            end: listed.end,
        };
        let mut cursor = Cursor(bytes);
        let mut batch = Vec::new();
        while !cursor.0.is_empty() {
            let index = cursor.u64().map_err(damaged)?;
            let term = cursor.u64().map_err(damaged)?;
            let event_time = cursor.u64().map_err(damaged)?;
            let length = cursor.u64().map_err(damaged)?;
            let payload = cursor
                .take(usize::try_from(length).unwrap_or(usize::MAX))
                .map_err(damaged)?
                .to_vec();
            top = (index, term);
            batch.push(Entry {
                index,
                term,
                event_time,
                payload,
            });
        }
        entries += batch.len() as u64;
        let _ = log.append(&batch)?;
    }
    let _ = log.sync()?;
    if top != manifest.top {
        return Err(BackupError::Manifest);
    }
    log.save_hard_state(HardState {
        current_term: top.1,
        voted_for: None,
        commit: Some(top.0),
    })?;
    Ok(Report {
        base: manifest.base,
        top,
        entries,
        objects: manifest.objects.len() as u64 + 1,
        not_included: NOT_INCLUDED,
    })
}
