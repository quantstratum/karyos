// SPDX-License-Identifier: Apache-2.0

//! A node's snapshots (quantstratum-docs:
//! karyos/design/cluster-dedup-and-snapshots.md §3, C8a), core neutral: a
//! snapshot is a last included index, its term and typed sections.
//!
//! - **Sections** (design S1(a)). A snapshot is a sequence of typed
//!   sections ([`SectionKind`]: consensus, sessions, timers, guards, the
//!   service's own bytes), each with a version (the schema's, or the
//!   service's and its schema's, as the caller packs them). Each is framed
//!   by a 24-byte header: magic `KRSN`, the kind, the version, the length.
//! - **Store.** Each snapshot is its own segment store (A2) in the
//!   snapshot directory, as a recording group's checkpoints are (A9),
//!   recording `id`, so a purge removes its files whole; A2 checks every
//!   write with its CRC-32C. The bytes are written and synced, the store
//!   closed, and only then is the manifest published.
//! - **Manifest.** One file, `snapshot-manifest`, replaced atomically
//!   (written, synced, renamed, its directory synced), lists the kept
//!   snapshots: id, index, term, length and a CRC-32C digest of all the
//!   snapshot's bytes. Its replacement is the publish. The design appends
//!   manifest records; a replaced file gives the same atomic publish and
//!   holds no more than [`MAX_KEEP`] entries, so it needs no purge of its
//!   own. The digest is CRC-32C until the owner decides on SHA-256 (item
//!   15).
//! - **Purge** (design S4(c)). After a publish the manifest keeps the
//!   newest [`SnapshotConfig::keep`] snapshots (2 proposed), and the
//!   others' files are removed. A crash while snapshot k + 1 is built
//!   leaves snapshot k complete. [`SnapshotConfig::log_floor`] gives the
//!   first log index to keep: the oldest kept snapshot's next index,
//!   lowered to retain up to [`SnapshotConfig::allowance`] log bytes below
//!   it for a slow follower. The log cannot purge a prefix yet
//!   (`RaftLog::purge_prefix` waits for A2 to drop leading segments).
//! - **When** (design S2). [`SnapshotConfig::due`] after `every_entries`
//!   entries or `every_bytes` log bytes since the last snapshot, never by
//!   time, so a seed gives the same snapshot points.
//! - **Recovery.** [`SnapshotStore::open`] reads the manifest and removes
//!   every store it does not name: a snapshot whose write or publish a
//!   crash cut short, or one a purge had not removed yet. A named snapshot
//!   was durable before its publish; one that no longer reads whole, or
//!   whose digest fails, is reported damaged and not used. A manifest that
//!   fails its CRC is refused.
//! - **Reads.** [`SnapshotStore::reader`] streams a snapshot section by
//!   section into the caller's buffer, and [`SnapshotStore::open`] and
//!   [`SnapshotStore::verify`] check one the same way: a section's bytes
//!   go to A2 in writes of at most [`WRITE_CHUNK`], so the memory a check
//!   holds is that and a fixed buffer, whatever the snapshot's size.
//!   [`SnapshotStore::read`] loads every section at once, for small ones.
//! - **Poison.** A failed write, sync, publish or purge poisons the store:
//!   it refuses writes until it is reopened, which finds what was
//!   published.
//! - **Configuration.** The defaults are the design's proposal (owner item
//!   37, not decided yet): keep 2, a 1 GiB allowance, a snapshot every
//!   1 Mi entries or 256 MiB. They are interim, and the owner's choice is a
//!   configuration change.
//!
//! Crash points, run on C2's simulated disk by karyos-sim's
//! `tests/snapshot_crash.rs`: every disk operation of a write (the
//! sections' appends, their sync, the close), of the manifest's
//! replacement and of the purge; recovery finds the last published
//! snapshot, whole, and nothing unpublished.

use std::io;
use std::path::{Path, PathBuf};

use karyos_archive::crc32c::{Crc32c, crc32c};
use karyos_archive::disk::Disk;
use karyos_archive::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

use crate::file::{self, Read};

#[cfg(test)]
mod tests;

/// The manifest's file.
pub const MANIFEST_FILE: &str = "snapshot-manifest";
/// Snapshots a manifest holds at most.
pub const MAX_KEEP: u32 = 16;
/// A section header's length.
pub const SECTION_HEADER: usize = 24;
/// The proposed snapshots kept (design S4; interim, owner item 37).
pub const DEFAULT_KEEP: u32 = 2;
/// The proposed catch-up allowance in log bytes (design S4(c); interim,
/// owner item 37).
pub const DEFAULT_ALLOWANCE: u64 = 1 << 30;
/// The proposed entries between snapshots (design S2; interim, owner item
/// 37).
pub const DEFAULT_EVERY_ENTRIES: u64 = 1 << 20;
/// The proposed log bytes between snapshots (design S2; interim, owner
/// item 37).
pub const DEFAULT_EVERY_BYTES: u64 = 256 << 20;

const SECTION_MAGIC: [u8; 4] = *b"KRSN";
/// The largest single write of a section's bytes: what a scan of the
/// snapshot (A2's recovery checks, [`SnapshotReader`]) holds at once.
pub const WRITE_CHUNK: usize = 64 * 1024;
/// The reader's buffer for bytes it checks without handing them out.
const SKIP_BUFFER: usize = 4096;
const MANIFEST_MAGIC: [u8; 4] = *b"KRSM";
const MANIFEST_VERSION: u32 = 1;
/// Magic, version, count, reserved.
const MANIFEST_HEADER: usize = 16;
/// Id, index, term, length, digest, reserved.
const MANIFEST_ENTRY: usize = 40;
const MANIFEST_MAX: usize = MANIFEST_HEADER + MANIFEST_ENTRY * 16 + 4;

const _: () = assert!(MAX_KEEP == 16);

/// Snapshot retention and timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnapshotConfig {
    /// Snapshots kept, 1 to [`MAX_KEEP`].
    pub keep: u32,
    /// Log bytes kept below the oldest kept snapshot for a slow follower.
    pub allowance: u64,
    /// Entries after which a snapshot is due.
    pub every_entries: u64,
    /// Log bytes after which a snapshot is due.
    pub every_bytes: u64,
}

impl Default for SnapshotConfig {
    /// The design's proposal, interim until the owner decides (item 37).
    fn default() -> Self {
        Self {
            keep: DEFAULT_KEEP,
            allowance: DEFAULT_ALLOWANCE,
            every_entries: DEFAULT_EVERY_ENTRIES,
            every_bytes: DEFAULT_EVERY_BYTES,
        }
    }
}

impl SnapshotConfig {
    /// Keeping `keep` snapshots.
    #[must_use]
    pub fn with_keep(mut self, keep: u32) -> Self {
        self.keep = keep;
        self
    }

    /// Keeping `allowance` log bytes below the oldest kept snapshot.
    #[must_use]
    pub fn with_allowance(mut self, allowance: u64) -> Self {
        self.allowance = allowance;
        self
    }

    /// A snapshot due after `every_entries` entries.
    #[must_use]
    pub fn with_every_entries(mut self, every_entries: u64) -> Self {
        self.every_entries = every_entries;
        self
    }

    /// A snapshot due after `every_bytes` log bytes.
    #[must_use]
    pub fn with_every_bytes(mut self, every_bytes: u64) -> Self {
        self.every_bytes = every_bytes;
        self
    }

    /// Whether a snapshot is due, `entries` entries and `bytes` log bytes
    /// after the last one.
    #[must_use]
    pub fn due(&self, entries: u64, bytes: u64) -> bool {
        entries >= self.every_entries || bytes >= self.every_bytes
    }

    /// The first log index to keep, for a log starting at `first` whose
    /// oldest kept snapshot includes `oldest`: `oldest + 1`, lowered while
    /// the log bytes kept below it stay within the allowance.
    /// `position(index)` is where entry `index` starts, for every index
    /// from `first` to `oldest + 1` (the end of the log for an index past
    /// it); `None` for an index it cannot place keeps `oldest + 1`.
    #[must_use]
    pub fn log_floor(&self, first: u64, oldest: u64, position: impl Fn(u64) -> Option<u64>) -> u64 {
        let Some(top) = oldest.checked_add(1) else {
            return oldest;
        };
        if first >= top {
            return first;
        }
        let Some(end) = position(top) else {
            return top;
        };
        // Positions grow with indices: the lowest index whose bytes up to
        // `top` fit the allowance, by bisection over [first, top].
        let fits = |index: u64| {
            position(index)
                .and_then(|start| end.checked_sub(start))
                .is_some_and(|kept| kept <= self.allowance)
        };
        let (mut low, mut high) = (first, top);
        while low < high {
            let Some(mid) = high
                .checked_sub(low)
                .and_then(|span| low.checked_add(span / 2))
            else {
                return top;
            };
            if fits(mid) {
                high = mid;
            } else {
                let Some(above) = mid.checked_add(1) else {
                    return top;
                };
                low = above;
            }
        }
        high
    }

    fn check(&self) -> Result<(), SnapshotError> {
        if self.keep == 0 || self.keep > MAX_KEEP {
            return Err(SnapshotError::Keep { keep: self.keep });
        }
        Ok(())
    }
}

/// A section's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SectionKind {
    /// The last index, term and configuration.
    Consensus,
    /// Client sessions and deduplication.
    Sessions,
    /// Timers.
    Timers,
    /// Guard state.
    Guards,
    /// The service's own bytes.
    Service,
}

impl SectionKind {
    fn code(self) -> u32 {
        match self {
            Self::Consensus => 1,
            Self::Sessions => 2,
            Self::Timers => 3,
            Self::Guards => 4,
            Self::Service => 5,
        }
    }

    fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::Consensus,
            2 => Self::Sessions,
            3 => Self::Timers,
            4 => Self::Guards,
            5 => Self::Service,
            _ => return None,
        })
    }
}

/// A section to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Section<'a> {
    /// Its type.
    pub kind: SectionKind,
    /// Its version.
    pub version: u64,
    /// Its bytes.
    pub bytes: &'a [u8],
}

impl<'a> Section<'a> {
    /// A `kind` section of `version` holding `bytes`.
    #[must_use]
    pub fn new(kind: SectionKind, version: u64, bytes: &'a [u8]) -> Self {
        Self {
            kind,
            version,
            bytes,
        }
    }
}

/// A section read back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SectionRead {
    /// Its type.
    pub kind: SectionKind,
    /// Its version.
    pub version: u64,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// A published snapshot, as the manifest names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnapshotInfo {
    /// Its store's recording id.
    pub id: u64,
    /// The last log index it includes.
    pub index: u64,
    /// That entry's term.
    pub term: u64,
    /// Its bytes, sections and headers.
    pub length: u64,
    /// The CRC-32C of its bytes.
    pub digest: u32,
}

/// What went wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotError {
    /// `keep` is 0 or above [`MAX_KEEP`].
    #[error("keep {keep} is not 1 to {MAX_KEEP}")]
    Keep {
        /// The value.
        keep: u32,
    },
    /// A snapshot must include a later index than the newest kept.
    #[error("index {index} is not past the newest snapshot's {newest}")]
    NotNewer {
        /// The index written.
        index: u64,
        /// The newest snapshot's.
        newest: u64,
    },
    /// A snapshot needs at least one section.
    #[error("a snapshot without sections")]
    Empty,
    /// The manifest is not one this version wrote whole.
    #[error("the snapshot manifest is damaged")]
    Manifest,
    /// The snapshot's bytes do not read back as its sections.
    #[error("snapshot {id} is damaged")]
    Damaged {
        /// Its id.
        id: u64,
    },
    /// An earlier failure: reopen the store.
    #[error("the snapshot store failed; reopen it")]
    Failed,
    /// Ids ran out.
    #[error("snapshot ids exhausted")]
    Exhausted,
    /// The segment store's error.
    #[error(transparent)]
    Store(#[from] SegmentError),
    /// The disk's error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A store opened.
#[derive(Debug)]
#[non_exhaustive]
pub struct Opened<D: Disk + Clone> {
    /// The store.
    pub store: SnapshotStore<D>,
    /// Ids of unpublished or purged stores removed.
    pub removed: Vec<u64>,
    /// Published snapshots that no longer read whole: not used.
    pub damaged: Vec<SnapshotInfo>,
}

/// A node's snapshot directory.
#[derive(Debug)]
pub struct SnapshotStore<D: Disk + Clone> {
    disk: D,
    dir: PathBuf,
    geometry: Geometry,
    config: SnapshotConfig,
    /// The kept snapshots, oldest first.
    kept: Vec<SnapshotInfo>,
    next_id: u64,
    failed: bool,
}

impl<D: Disk + Clone> SnapshotStore<D> {
    /// Opens the snapshots in `dir`, an empty directory included, with
    /// `geometry` for their stores; see the module's recovery.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Keep`], [`SnapshotError::Manifest`], and the
    /// disk's errors.
    pub fn open(
        mut disk: D,
        dir: &Path,
        geometry: Geometry,
        config: SnapshotConfig,
    ) -> Result<Opened<D>, SnapshotError> {
        config.check()?;
        let named = match file::read(&mut disk, dir, MANIFEST_FILE, MANIFEST_MAX)? {
            Read::Missing => Vec::new(),
            Read::Bytes(bytes) => decode_manifest(&bytes).ok_or(SnapshotError::Manifest)?,
            Read::TooLong(_) => return Err(SnapshotError::Manifest),
        };
        let ids = recordings(&disk.list(dir)?);
        let mut removed = Vec::new();
        for id in &ids {
            if !named.iter().any(|info| info.id == *id) {
                remove_recording(&mut disk, dir, *id)?;
                removed.push(*id);
            }
        }
        if !removed.is_empty() {
            disk.sync_dir(dir)?;
        }
        let mut kept = Vec::new();
        let mut damaged = Vec::new();
        for info in &named {
            match verify_snapshot(disk.clone(), dir, geometry, info) {
                Ok(()) => kept.push(*info),
                Err(SnapshotError::Io(error)) => return Err(SnapshotError::Io(error)),
                Err(_) => damaged.push(*info),
            }
        }
        let highest = ids
            .iter()
            .copied()
            .chain(named.iter().map(|info| info.id))
            .max()
            .unwrap_or(0);
        let next_id = highest.checked_add(1).ok_or(SnapshotError::Exhausted)?;
        Ok(Opened {
            store: Self {
                disk,
                dir: dir.to_path_buf(),
                geometry,
                config,
                kept,
                next_id,
                failed: false,
            },
            removed,
            damaged,
        })
    }

    /// The kept snapshots, oldest first.
    #[must_use]
    pub fn snapshots(&self) -> &[SnapshotInfo] {
        &self.kept
    }

    /// The newest kept snapshot.
    #[must_use]
    pub fn latest(&self) -> Option<SnapshotInfo> {
        self.kept.last().copied()
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> SnapshotConfig {
        self.config
    }

    /// Writes a snapshot including log index `index` of term `term`, made
    /// of `sections` in order, publishes it and purges what the manifest
    /// no longer keeps. Durable and published on return.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::NotNewer`] and [`SnapshotError::Empty`], which
    /// change nothing; [`SnapshotError::Failed`] after an earlier failure;
    /// the store's and the disk's errors, which poison the store: the
    /// snapshot may then be published or not, and a reopen tells.
    pub fn write(
        &mut self,
        index: u64,
        term: u64,
        sections: &[Section<'_>],
    ) -> Result<SnapshotInfo, SnapshotError> {
        if self.failed {
            return Err(SnapshotError::Failed);
        }
        if let Some(newest) = self.latest().filter(|newest| index <= newest.index) {
            return Err(SnapshotError::NotNewer {
                index,
                newest: newest.index,
            });
        }
        if sections.is_empty() {
            return Err(SnapshotError::Empty);
        }
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(SnapshotError::Exhausted)?;
        self.failed = true;
        self.next_id = next;
        let (length, digest) = self.write_sections(id, sections)?;
        let info = SnapshotInfo {
            id,
            index,
            term,
            length,
            digest,
        };
        let mut kept = self.kept.clone();
        kept.push(info);
        let keep = usize::try_from(self.config.keep).unwrap_or(usize::MAX);
        let purged: Vec<SnapshotInfo> = match kept.len().checked_sub(keep) {
            Some(excess) if excess > 0 => kept.drain(..excess).collect(),
            _ => Vec::new(),
        };
        file::replace(
            &mut self.disk,
            &self.dir,
            MANIFEST_FILE,
            &encode_manifest(&kept),
        )?;
        self.kept = kept;
        for old in &purged {
            remove_recording(&mut self.disk, &self.dir, old.id)?;
        }
        if !purged.is_empty() {
            self.disk.sync_dir(&self.dir)?;
        }
        self.failed = false;
        Ok(info)
    }

    /// The sections of `info`, a kept snapshot, checked against its length
    /// and digest, every section's bytes in memory at once: for small
    /// snapshots and tests. [`SnapshotStore::reader`] streams them.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Damaged`] for bytes that do not read back whole,
    /// and the store's and the disk's errors.
    pub fn read(&self, info: &SnapshotInfo) -> Result<Vec<SectionRead>, SnapshotError> {
        let mut reader = self.reader(info)?;
        let mut sections = Vec::new();
        while let Some(header) = reader.next_section()? {
            let length = usize::try_from(header.length).map_err(|_| reader.damaged())?;
            let mut bytes = vec![0u8; length];
            let mut filled = 0;
            while let Some(rest) = bytes.get_mut(filled..).filter(|rest| !rest.is_empty()) {
                let read = reader.read(rest)?;
                if read == 0 {
                    return Err(reader.damaged());
                }
                filled = filled.checked_add(read).ok_or_else(|| reader.damaged())?;
            }
            sections.push(SectionRead {
                kind: header.kind,
                version: header.version,
                bytes,
            });
        }
        Ok(sections)
    }

    /// A reader of `info`'s sections, in order and in chunks, holding no
    /// more than a fixed buffer and A2's scan of one write
    /// ([`WRITE_CHUNK`]).
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Damaged`] for a store that does not hold the
    /// snapshot's length, and the store's and the disk's errors.
    pub fn reader(&self, info: &SnapshotInfo) -> Result<SnapshotReader<D>, SnapshotError> {
        SnapshotReader::open(self.disk.clone(), &self.dir, self.geometry, info)
    }

    /// Checks `info` whole, its sections' framing and its digest, streaming
    /// it: what [`SnapshotStore::open`] runs on each kept snapshot.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Damaged`], and the store's and the disk's errors.
    pub fn verify(&self, info: &SnapshotInfo) -> Result<(), SnapshotError> {
        verify_snapshot(self.disk.clone(), &self.dir, self.geometry, info)
    }

    /// Writes `sections` into a new store `id`, synced and closed; their
    /// length and digest.
    fn write_sections(
        &mut self,
        id: u64,
        sections: &[Section<'_>],
    ) -> Result<(u64, u32), SnapshotError> {
        let mut store = SegmentStore::create(
            self.disk.clone(),
            &self.dir,
            id,
            self.geometry,
            SyncPolicy::None,
            0,
        )?;
        let mut digest = Crc32c::new();
        let mut at = 0;
        for section in sections {
            let header = section_header(section)?;
            digest.update(&header);
            at = store.append(at, &header)?;
            // In chunks: A2 checks each write whole at recovery, so a write
            // bounds the memory a scan of the snapshot needs.
            for chunk in section.bytes.chunks(WRITE_CHUNK) {
                digest.update(chunk);
                at = store.append(at, chunk)?;
            }
        }
        let _ = store.close_synced()?;
        Ok((at, digest.finish()))
    }
}

/// A section's header.
fn section_header(section: &Section<'_>) -> Result<[u8; SECTION_HEADER], SnapshotError> {
    let length = u64::try_from(section.bytes.len()).map_err(|_| SegmentError::PositionOverflow)?;
    let mut header = [0u8; SECTION_HEADER];
    let (magic, rest) = header.split_at_mut(4);
    magic.copy_from_slice(&SECTION_MAGIC);
    let (kind, rest) = rest.split_at_mut(4);
    kind.copy_from_slice(&section.kind.code().to_le_bytes());
    let (version, rest) = rest.split_at_mut(8);
    version.copy_from_slice(&section.version.to_le_bytes());
    rest.copy_from_slice(&length.to_le_bytes());
    Ok(header)
}

/// A section's header, as a reader meets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SectionHeader {
    /// Its type.
    pub kind: SectionKind,
    /// Its version.
    pub version: u64,
    /// Its bytes.
    pub length: u64,
}

/// A snapshot read section by section, in chunks
/// ([`SnapshotStore::reader`]).
///
/// [`SnapshotReader::next_section`] moves to the next section, checking
/// what the caller left of the current one; [`SnapshotReader::read`] hands
/// out the current section's bytes. A2 checked every write's CRC when the
/// store opened; the snapshot's digest covers every byte, so it is known
/// only at the end: `next_section` returns `None` only once it matched,
/// and a caller must treat what it read as unverified until then.
#[derive(Debug)]
pub struct SnapshotReader<D: Disk> {
    store: SegmentStore<D>,
    id: u64,
    length: u64,
    expected: u32,
    digest: Crc32c,
    /// The next position to read.
    at: u64,
    /// The current section's end.
    section_end: u64,
    finished: bool,
}

impl<D: Disk> SnapshotReader<D> {
    fn open(
        disk: D,
        dir: &Path,
        geometry: Geometry,
        info: &SnapshotInfo,
    ) -> Result<Self, SnapshotError> {
        let damaged = SnapshotError::Damaged { id: info.id };
        let store =
            match SegmentStore::open_verified(disk, dir, info.id, geometry, SyncPolicy::None) {
                Ok(store) => store,
                Err(SegmentError::Io(error)) => return Err(SnapshotError::Io(error)),
                Err(_) => return Err(damaged),
            };
        if store.start() != 0 || store.written() != info.length || !store.gaps().is_empty() {
            return Err(damaged);
        }
        Ok(Self {
            store,
            id: info.id,
            length: info.length,
            expected: info.digest,
            digest: Crc32c::new(),
            at: 0,
            section_end: 0,
            finished: false,
        })
    }

    fn damaged(&self) -> SnapshotError {
        SnapshotError::Damaged { id: self.id }
    }

    /// Reads `buf` whole at the current position, into the digest.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), SnapshotError> {
        let length = u64::try_from(buf.len()).map_err(|_| self.damaged())?;
        let end = self.at.checked_add(length).ok_or_else(|| self.damaged())?;
        if end > self.length {
            return Err(self.damaged());
        }
        if let Err(error) = self.store.read(self.at, buf) {
            return Err(match error {
                SegmentError::Io(error) => SnapshotError::Io(error),
                _ => self.damaged(),
            });
        }
        self.digest.update(buf);
        self.at = end;
        Ok(())
    }

    /// The next section's header, after checking what is left of the
    /// current one; `None` at the end, once the digest matched.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Damaged`] for a header, a length or a digest that
    /// does not hold, and the store's and the disk's errors.
    pub fn next_section(&mut self) -> Result<Option<SectionHeader>, SnapshotError> {
        if self.finished {
            return Ok(None);
        }
        let mut skip = [0u8; SKIP_BUFFER];
        while self.at < self.section_end {
            let left = self
                .section_end
                .checked_sub(self.at)
                .ok_or_else(|| self.damaged())?;
            let take = usize::try_from(left).map_or(SKIP_BUFFER, |left| left.min(SKIP_BUFFER));
            let chunk = skip.get_mut(..take).ok_or_else(|| self.damaged())?;
            self.fill(chunk)?;
        }
        if self.at == self.length {
            if self.digest.finish() != self.expected {
                return Err(self.damaged());
            }
            self.finished = true;
            return Ok(None);
        }
        let mut header = [0u8; SECTION_HEADER];
        self.fill(&mut header)?;
        let damaged = || SnapshotError::Damaged { id: self.id };
        let (magic, fields) = header.split_first_chunk::<4>().ok_or_else(damaged)?;
        let (kind, fields) = fields.split_first_chunk::<4>().ok_or_else(damaged)?;
        let (version, fields) = fields.split_first_chunk::<8>().ok_or_else(damaged)?;
        let (length, _) = fields.split_first_chunk::<8>().ok_or_else(damaged)?;
        if *magic != SECTION_MAGIC {
            return Err(damaged());
        }
        let kind = SectionKind::from_code(u32::from_le_bytes(*kind)).ok_or_else(damaged)?;
        let length = u64::from_le_bytes(*length);
        let end = self
            .at
            .checked_add(length)
            .filter(|end| *end <= self.length)
            .ok_or_else(damaged)?;
        self.section_end = end;
        Ok(Some(SectionHeader {
            kind,
            version: u64::from_le_bytes(*version),
            length,
        }))
    }

    /// Reads up to `buf.len()` bytes of the current section; 0 at its end.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Damaged`] for bytes that do not read back, and the
    /// store's and the disk's errors.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SnapshotError> {
        let left = self
            .section_end
            .checked_sub(self.at)
            .ok_or_else(|| self.damaged())?;
        let take = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        let chunk = buf.get_mut(..take).ok_or_else(|| self.damaged())?;
        self.fill(chunk)?;
        Ok(take)
    }
}

/// Checks snapshot `info` in `dir` whole, streaming it.
fn verify_snapshot<D: Disk>(
    disk: D,
    dir: &Path,
    geometry: Geometry,
    info: &SnapshotInfo,
) -> Result<(), SnapshotError> {
    let mut reader = SnapshotReader::open(disk, dir, geometry, info)?;
    while reader.next_section()?.is_some() {}
    Ok(())
}

/// The manifest's bytes.
fn encode_manifest(kept: &[SnapshotInfo]) -> Vec<u8> {
    let count = u32::try_from(kept.len()).unwrap_or(u32::MAX);
    let mut bytes = Vec::with_capacity(MANIFEST_MAX);
    bytes.extend_from_slice(&MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    for info in kept {
        bytes.extend_from_slice(&info.id.to_le_bytes());
        bytes.extend_from_slice(&info.index.to_le_bytes());
        bytes.extend_from_slice(&info.term.to_le_bytes());
        bytes.extend_from_slice(&info.length.to_le_bytes());
        bytes.extend_from_slice(&info.digest.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
    }
    let sum = crc32c(&bytes);
    bytes.extend_from_slice(&sum.to_le_bytes());
    bytes
}

/// The snapshots a manifest names, if this version wrote it whole.
fn decode_manifest(bytes: &[u8]) -> Option<Vec<SnapshotInfo>> {
    let (body, crc) = bytes.split_last_chunk::<4>()?;
    if u32::from_le_bytes(*crc) != crc32c(body) {
        return None;
    }
    let (header, entries) = body.split_first_chunk::<MANIFEST_HEADER>()?;
    let (magic, fields) = header.split_first_chunk::<4>()?;
    let (version, fields) = fields.split_first_chunk::<4>()?;
    let (count, reserved) = fields.split_first_chunk::<4>()?;
    if *magic != MANIFEST_MAGIC
        || u32::from_le_bytes(*version) != MANIFEST_VERSION
        || reserved.iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let count = usize::try_from(u32::from_le_bytes(*count)).ok()?;
    if entries.len() != count.checked_mul(MANIFEST_ENTRY)? {
        return None;
    }
    entries
        .as_chunks::<MANIFEST_ENTRY>()
        .0
        .iter()
        .map(|entry| {
            let (id, rest) = entry.split_first_chunk::<8>()?;
            let (index, rest) = rest.split_first_chunk::<8>()?;
            let (term, rest) = rest.split_first_chunk::<8>()?;
            let (length, rest) = rest.split_first_chunk::<8>()?;
            let (digest, _) = rest.split_first_chunk::<4>()?;
            Some(SnapshotInfo {
                id: u64::from_le_bytes(*id),
                index: u64::from_le_bytes(*index),
                term: u64::from_le_bytes(*term),
                length: u64::from_le_bytes(*length),
                digest: u32::from_le_bytes(*digest),
            })
        })
        .collect()
}

/// The recording ids that have segment files among `names`.
fn recordings(names: &[String]) -> Vec<u64> {
    let mut ids: Vec<u64> = names
        .iter()
        .filter(|name| name.ends_with(".seg") || name.ends_with(".idx"))
        .filter_map(|name| name.split_once('-'))
        .filter_map(|(id, _)| u64::from_str_radix(id, 16).ok())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Removes every segment file of recording `id`; the caller syncs `dir`.
fn remove_recording<D: Disk>(disk: &mut D, dir: &Path, id: u64) -> io::Result<()> {
    let prefix = format!("{id:016x}-");
    for name in disk.list(dir)? {
        if name.starts_with(&prefix) && (name.ends_with(".seg") || name.ends_with(".idx")) {
            disk.remove(&dir.join(&name))?;
        }
    }
    Ok(())
}
