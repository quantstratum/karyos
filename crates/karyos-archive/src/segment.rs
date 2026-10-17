// SPDX-License-Identifier: Apache-2.0

//! The segment store of one recording (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A2; SPEC §8.1, ADR-0023).
//!
//! - **Layout.** A recording's stream positions are kept in segment files
//!   of `segment_length` bytes, a checked multiple of the term length. The
//!   segment of position `p` starts at `p - p % segment_length`, and `p` is
//!   at that offset in its file, so the frames sit as in the log and a
//!   replay reads by position. Each segment `<recording>-<base>.seg` has an
//!   index `<recording>-<base>.idx`: a header, then one entry per write,
//!   each with the CRC-32C of the written range and its own.
//! - **Positions.** `written` is the end of the last indexed write.
//!   `durable` covers the data and the index both: a sync makes the data
//!   durable, then the index, and only then advances `durable` to the
//!   `written` it started from. A new segment's files and their directory
//!   entries are durable before anything in it is written.
//! - **Policies.** No sync; sync per segment (a finished segment, on the
//!   append that rolls past it, and the close); or sync when
//!   [`SegmentStore::tick`] finds the interval passed, a finished segment
//!   included (its files stay open until then, so no sync runs on the
//!   write path; a roll past four waiting segments syncs them inline). An explicit [`SegmentStore::sync`] is always possible;
//!   under no sync it cannot cover a segment finished without one, so
//!   `durable` stays. Under every policy, the append that rolls into a new
//!   segment creates its files and syncs them and their directory entries:
//!   that write-path latency is the price of a durable segment start.
//! - **Recovery.** [`SegmentStore::recover`] walks the indexes in order and
//!   stops at the first entry that is torn, whose own CRC fails, that does
//!   not continue the previous one, or whose data does not match its CRC.
//!   The index is cut there, the data file shortened, later segments
//!   dropped and the cut reported; everything kept is synced, so `durable`
//!   equals `written` afterwards. A write the index does not cover was
//!   never `written`, so a torn write is never read back. The data file is
//!   shortened to `written`, so no stale byte past it lingers.
//! - **Headers.** Only the last segment can be one being created, and
//!   recovery removes it: its index header is missing, short or zeroed, or
//!   torn (failing its CRC) with no data and no entry behind it. Creation
//!   makes the header durable before any write, so a torn header with
//!   data or entries behind it is corruption. Any other bad header is a
//!   typed error that removes nothing: one missing or torn before the last
//!   segment, a corrupt one, one of another format version, one naming
//!   another recording or geometry, or one whose start is outside its
//!   segment.
//!
//! A gap in the stream is not the store's: appends are contiguous, and
//! the recorder (A4) records a gap as its own record.

#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};

pub use crate::disk::{Disk, StdDisk};

use crate::crc32c::crc32c;

/// The default segment length, where the term length divides it.
pub const DEFAULT_SEGMENT_LENGTH: u64 = 128 << 20;

/// "KYSX", the index magic.
const MAGIC: u32 = u32::from_le_bytes(*b"KYSX");
/// The index format version.
const VERSION: u32 = 1;
/// The index header's length.
const HEADER: u64 = 48;
/// An index entry's length.
const ENTRY: u64 = 32;

/// Finished segments the interval policy keeps open for its next tick; a
/// roll past this many syncs them inline, so a store that is never ticked
/// holds a bounded number of files.
const MAX_FINISHED: usize = 4;

/// A recording's segment geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    term_length: u32,
    segment_length: u64,
}

impl Geometry {
    /// Segments of `segment_length` bytes for terms of `term_length`.
    ///
    /// # Errors
    ///
    /// [`SegmentError::InvalidGeometry`] unless the term length is nonzero
    /// and the segment length is a multiple of it, at most `u32::MAX`.
    pub fn new(term_length: u32, segment_length: u64) -> Result<Self, SegmentError> {
        let valid = term_length > 0
            && segment_length > 0
            && segment_length <= u64::from(u32::MAX)
            && segment_length.is_multiple_of(u64::from(term_length));
        if !valid {
            return Err(SegmentError::InvalidGeometry);
        }
        Ok(Self {
            term_length,
            segment_length,
        })
    }

    /// [`DEFAULT_SEGMENT_LENGTH`] where `term_length` divides it, else one
    /// term per segment.
    ///
    /// # Errors
    ///
    /// As [`Geometry::new`].
    pub fn with_default_length(term_length: u32) -> Result<Self, SegmentError> {
        let term = u64::from(term_length);
        let length = if term > 0 && term <= DEFAULT_SEGMENT_LENGTH {
            DEFAULT_SEGMENT_LENGTH - DEFAULT_SEGMENT_LENGTH % term
        } else {
            term
        };
        Self::new(term_length, length)
    }

    /// The term length.
    #[must_use]
    pub const fn term_length(&self) -> u32 {
        self.term_length
    }

    /// The segment length.
    #[must_use]
    pub const fn segment_length(&self) -> u64 {
        self.segment_length
    }

    /// The base of the segment holding `position`.
    const fn base_of(&self, position: u64) -> u64 {
        position - position % self.segment_length
    }
}

/// When the store syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPolicy {
    /// Never on its own; `durable` advances only by an explicit sync.
    None,
    /// When a segment is finished, and at the close.
    PerSegment,
    /// When [`SegmentStore::tick`] finds `interval_ns` passed since the
    /// last sync, and at the close.
    Every {
        /// The interval, in nanoseconds of the caller's clock.
        interval_ns: u64,
    },
}

/// Why recovery cut a recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutReason {
    /// An index entry was only partly written.
    TornEntry,
    /// An index entry's own CRC failed.
    EntryChecksum,
    /// An entry does not continue the previous one, or leaves its segment.
    NotContiguous,
    /// The data does not match its entry's CRC: a torn data write.
    DataChecksum,
    /// A segment's index header is missing or torn.
    Header,
}

/// Where recovery cut a recording, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cut {
    /// The position the recording now ends at.
    pub position: u64,
    /// Why.
    pub reason: CutReason,
}

/// The segment store's errors.
#[derive(Debug, thiserror::Error)]
pub enum SegmentError {
    /// The geometry is invalid.
    #[error("invalid segment geometry")]
    InvalidGeometry,
    /// The recording already has files.
    #[error("recording {recording} already exists")]
    Exists {
        /// The recording.
        recording: u64,
    },
    /// The recording has no recoverable segment.
    #[error("recording {recording} has no recoverable segment")]
    NotFound {
        /// The recording.
        recording: u64,
    },
    /// A write does not start at the written position.
    #[error("write at {got}, the written position is {expected}")]
    NotContiguous {
        /// The written position.
        expected: u64,
        /// The write's position.
        got: u64,
    },
    /// A read outside the recorded range.
    #[error("read of [{position}, +{length}) outside [{start}, {written})")]
    OutOfRange {
        /// The read's position.
        position: u64,
        /// The read's length.
        length: u64,
        /// The recording's start.
        start: u64,
        /// The written position.
        written: u64,
    },
    /// A position does not fit 64 bits.
    #[error("position overflow")]
    PositionOverflow,
    /// An earlier operation failed: the store's state on disk is unknown
    /// until it is recovered.
    #[error("the store failed earlier and must be recovered")]
    Failed,
    /// A segment's index header is bad where recovery cannot treat it as a
    /// segment being created; nothing was removed.
    #[error("the index header of the segment at {base} is bad: {problem:?}")]
    BadHeader {
        /// The segment's base.
        base: u64,
        /// What is wrong.
        problem: HeaderProblem,
    },
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What is wrong with an index header recovery refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProblem {
    /// Missing, short, zeroed or torn, before the last segment; or a data
    /// file missing under its index.
    Incomplete,
    /// Torn (failing its CRC) with data or entries behind it: written and
    /// made durable at creation, then damaged.
    Corrupt,
    /// Another format (magic or version) under a valid CRC.
    Foreign,
    /// Another recording, base or geometry under a valid CRC: the store is
    /// opened with the wrong arguments.
    Mismatch,
    /// Its start lies outside its segment.
    OutOfRange,
}

/// What reading an index header gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderRead {
    Valid(Header),
    /// Missing, short or zeroed.
    Missing,
    /// Whole but failing its CRC.
    Torn,
    /// A valid CRC over another magic or version.
    Foreign,
}

/// A recovered store.
#[derive(Debug)]
pub struct Recovered<D: Disk> {
    /// The store, open for appends at its written position.
    pub store: SegmentStore<D>,
    /// Where recovery cut the recording, if it did.
    pub cut: Option<Cut>,
    /// Segments after the cut, removed.
    pub dropped_segments: u32,
}

/// The open segment.
#[derive(Debug)]
struct Open<F> {
    base: u64,
    data: F,
    index: F,
    entries: u64,
    /// Written since its last sync.
    dirty: bool,
}

/// The segment store of one recording.
#[derive(Debug)]
pub struct SegmentStore<D: Disk> {
    disk: D,
    dir: PathBuf,
    recording: u64,
    geometry: Geometry,
    policy: SyncPolicy,
    start: u64,
    written: u64,
    durable: u64,
    current: Option<Open<D::File>>,
    /// Finished segments the interval policy syncs at its next tick.
    finished: Vec<Open<D::File>>,
    /// A segment was finished without a sync (no-sync policy): `durable`
    /// can no longer pass it.
    unsynced_behind: bool,
    last_sync_ns: u64,
    /// A sync ran since the last tick (explicit, or a roll's).
    synced_since_tick: bool,
    failed: bool,
    /// Test only: the index is not synced (a negative control).
    #[cfg(test)]
    skip_index_sync: bool,
}

/// An index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    start: u64,
    length: u32,
    data_crc: u32,
}

impl Entry {
    fn encode(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        put(&mut bytes, 0, &self.start.to_le_bytes());
        put(&mut bytes, 8, &self.length.to_le_bytes());
        put(&mut bytes, 12, &self.data_crc.to_le_bytes());
        let crc = crc32c(bytes.get(..28).unwrap_or_default());
        put(&mut bytes, 28, &crc.to_le_bytes());
        bytes
    }

    /// The entry in `bytes`, if its own CRC holds.
    fn decode(bytes: &[u8; 32]) -> Option<Self> {
        if crc32c(bytes.get(..28)?) != u32_at(bytes, 28)? {
            return None;
        }
        Some(Self {
            start: u64_at(bytes, 0)?,
            length: u32_at(bytes, 8)?,
            data_crc: u32_at(bytes, 12)?,
        })
    }

    fn end(self) -> Option<u64> {
        self.start.checked_add(u64::from(self.length))
    }
}

/// An index header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    recording: u64,
    base: u64,
    start: u64,
    segment_length: u64,
    term_length: u32,
}

impl Header {
    fn encode(self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        put(&mut bytes, 0, &MAGIC.to_le_bytes());
        put(&mut bytes, 4, &VERSION.to_le_bytes());
        put(&mut bytes, 8, &self.recording.to_le_bytes());
        put(&mut bytes, 16, &self.base.to_le_bytes());
        put(&mut bytes, 24, &self.start.to_le_bytes());
        put(&mut bytes, 32, &self.segment_length.to_le_bytes());
        put(&mut bytes, 40, &self.term_length.to_le_bytes());
        let crc = crc32c(bytes.get(..44).unwrap_or_default());
        put(&mut bytes, 44, &crc.to_le_bytes());
        bytes
    }

    fn read(bytes: Option<&[u8; 48]>) -> HeaderRead {
        let Some(bytes) = bytes else {
            return HeaderRead::Missing;
        };
        if bytes.iter().all(|byte| *byte == 0) {
            return HeaderRead::Missing;
        }
        let checked = bytes
            .get(..44)
            .map(crc32c)
            .zip(u32_at(bytes, 44))
            .is_some_and(|(crc, stored)| crc == stored);
        if !checked {
            return HeaderRead::Torn;
        }
        if u32_at(bytes, 0) != Some(MAGIC) || u32_at(bytes, 4) != Some(VERSION) {
            return HeaderRead::Foreign;
        }
        match (
            u64_at(bytes, 8),
            u64_at(bytes, 16),
            u64_at(bytes, 24),
            u64_at(bytes, 32),
            u32_at(bytes, 40),
        ) {
            (Some(recording), Some(base), Some(start), Some(segment_length), Some(term_length)) => {
                HeaderRead::Valid(Self {
                    recording,
                    base,
                    start,
                    segment_length,
                    term_length,
                })
            }
            _ => HeaderRead::Missing,
        }
    }
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    if let Some(target) = at
        .checked_add(value.len())
        .and_then(|end| bytes.get_mut(at..end))
    {
        target.copy_from_slice(value);
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn data_name(recording: u64, base: u64) -> String {
    format!("{recording:016x}-{base:016x}.seg")
}

fn index_name(recording: u64, base: u64) -> String {
    format!("{recording:016x}-{base:016x}.idx")
}

/// The segment bases of `recording` among `names`, in order.
fn bases(recording: u64, names: &[String]) -> Vec<u64> {
    let prefix = format!("{recording:016x}-");
    let mut bases: Vec<u64> = names
        .iter()
        .filter_map(|name| {
            let rest = name.strip_prefix(&prefix)?;
            let hex = rest
                .strip_suffix(".seg")
                .or_else(|| rest.strip_suffix(".idx"))?;
            (hex.len() == 16)
                .then(|| u64::from_str_radix(hex, 16).ok())
                .flatten()
        })
        .collect();
    bases.sort_unstable();
    bases.dedup();
    bases
}

/// The offset of index entry `entry`.
fn entry_offset(entry: u64) -> Option<u64> {
    entry.checked_mul(ENTRY)?.checked_add(HEADER)
}

impl<D: Disk> SegmentStore<D> {
    /// Creates recording `recording` in `dir`, starting at `start`. Its
    /// first segment's files and directory entries are durable on return.
    ///
    /// # Errors
    ///
    /// [`SegmentError::Exists`] when the recording has files in `dir`, and
    /// the operating system's errors.
    pub fn create(
        mut disk: D,
        dir: &Path,
        recording: u64,
        geometry: Geometry,
        policy: SyncPolicy,
        start: u64,
    ) -> Result<Self, SegmentError> {
        if !bases(recording, &disk.list(dir)?).is_empty() {
            return Err(SegmentError::Exists { recording });
        }
        let mut store = Self {
            disk,
            dir: dir.to_path_buf(),
            recording,
            geometry,
            policy,
            start,
            written: start,
            durable: start,
            current: None,
            finished: Vec::new(),
            unsynced_behind: false,
            last_sync_ns: 0,
            synced_since_tick: false,
            failed: false,
            #[cfg(test)]
            skip_index_sync: false,
        };
        let base = geometry.base_of(start);
        let open = store.open_new(base, start)?;
        store.current = Some(open);
        Ok(store)
    }

    /// The recording's first position.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// The end of the last indexed write.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }

    /// The end of what a sync made durable, data and index both.
    #[must_use]
    pub const fn durable(&self) -> u64 {
        self.durable
    }

    /// The geometry.
    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Creates the segment at `base` (its index header naming `start`),
    /// then makes its files and their directory entries durable.
    fn open_new(&mut self, base: u64, start: u64) -> Result<Open<D::File>, SegmentError> {
        let data_path = self.dir.join(data_name(self.recording, base));
        let index_path = self.dir.join(index_name(self.recording, base));
        let data = self.disk.create(&data_path)?;
        let index = self.disk.create(&index_path)?;
        let header = Header {
            recording: self.recording,
            base,
            start,
            segment_length: self.geometry.segment_length,
            term_length: self.geometry.term_length,
        };
        self.disk.write_at(&index, 0, &header.encode())?;
        self.disk.sync(&index)?;
        self.disk.sync(&data)?;
        self.disk.sync_dir(&self.dir)?;
        Ok(Open {
            base,
            data,
            index,
            entries: 0,
            dirty: false,
        })
    }

    /// Fails the store on an error: its state on disk is unknown.
    fn guard<T>(&mut self, result: Result<T, SegmentError>) -> Result<T, SegmentError> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Appends `bytes` at `position`, which must be the written position.
    /// Returns the new written position.
    ///
    /// # Errors
    ///
    /// [`SegmentError::NotContiguous`] and
    /// [`SegmentError::PositionOverflow`], which change nothing;
    /// [`SegmentError::Failed`] after an earlier failure; the operating
    /// system's errors, after which the store fails until recovered.
    pub fn append(&mut self, position: u64, bytes: &[u8]) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        if position != self.written {
            return Err(SegmentError::NotContiguous {
                expected: self.written,
                got: position,
            });
        }
        let length = u64::try_from(bytes.len()).map_err(|_| SegmentError::PositionOverflow)?;
        position
            .checked_add(length)
            .ok_or(SegmentError::PositionOverflow)?;
        let result = self.append_all(bytes);
        self.guard(result)
    }

    fn append_all(&mut self, mut bytes: &[u8]) -> Result<u64, SegmentError> {
        while !bytes.is_empty() {
            let base = self.geometry.base_of(self.written);
            if self.current.as_ref().is_none_or(|open| open.base != base) {
                self.roll(base)?;
            }
            let room = base
                .checked_add(self.geometry.segment_length)
                .and_then(|end| end.checked_sub(self.written))
                .ok_or(SegmentError::PositionOverflow)?;
            let take = usize::try_from(room).map_or(bytes.len(), |room| room.min(bytes.len()));
            let (chunk, rest) = bytes.split_at(take);
            self.write_chunk(chunk)?;
            bytes = rest;
        }
        Ok(self.written)
    }

    /// Writes `chunk`, which fits the open segment, then its entry.
    fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), SegmentError> {
        let written = self.written;
        let open = self.current.as_mut().ok_or(SegmentError::Failed)?;
        let length = u32::try_from(chunk.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let entry = Entry {
            start: written,
            length,
            data_crc: crc32c(chunk),
        };
        let offset = written
            .checked_sub(open.base)
            .ok_or(SegmentError::PositionOverflow)?;
        let entry_at = entry_offset(open.entries).ok_or(SegmentError::PositionOverflow)?;
        self.disk.write_at(&open.data, offset, chunk)?;
        self.disk.write_at(&open.index, entry_at, &entry.encode())?;
        open.entries = open
            .entries
            .checked_add(1)
            .ok_or(SegmentError::PositionOverflow)?;
        open.dirty = true;
        self.written = entry.end().ok_or(SegmentError::PositionOverflow)?;
        Ok(())
    }

    /// Finishes the open segment, synced unless the policy is no sync, and
    /// opens the one at `base`.
    fn roll(&mut self, base: u64) -> Result<(), SegmentError> {
        let dirty = self.current.as_ref().is_some_and(|open| open.dirty);
        match self.policy {
            SyncPolicy::None if dirty => self.unsynced_behind = true,
            SyncPolicy::PerSegment if dirty => self.sync_open()?,
            // The next tick syncs it: no sync on the write path, unless
            // more than `MAX_FINISHED` wait (no tick for many rolls).
            SyncPolicy::Every { .. } if dirty => {
                if let Some(open) = self.current.take() {
                    self.finished.push(open);
                }
                if self.finished.len() > MAX_FINISHED {
                    self.sync_open()?;
                }
            }
            _ => {}
        }
        self.current = None;
        let open = self.open_new(base, base)?;
        self.current = Some(open);
        Ok(())
    }

    /// Syncs the open segment's data, then its index, then advances
    /// `durable` to the written position it started from.
    fn sync_open(&mut self) -> Result<(), SegmentError> {
        let target = self.written;
        for open in &self.finished {
            self.disk.sync(&open.data)?;
            self.disk.sync(&open.index)?;
        }
        self.finished.clear();
        if let Some(open) = self.current.as_mut()
            && open.dirty
        {
            self.disk.sync(&open.data)?;
            #[cfg(test)]
            let skip = self.skip_index_sync;
            #[cfg(not(test))]
            let skip = false;
            if !skip {
                self.disk.sync(&open.index)?;
            }
            open.dirty = false;
        }
        if !self.unsynced_behind {
            self.durable = target;
        }
        self.synced_since_tick = true;
        Ok(())
    }

    /// Makes everything written durable, data then index, and returns the
    /// durable position. Under no sync, a segment finished without one
    /// keeps `durable` where it was.
    ///
    /// # Errors
    ///
    /// [`SegmentError::Failed`] after an earlier failure, and the operating
    /// system's errors, after which the store fails until recovered.
    pub fn sync(&mut self) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        let result = self.sync_open();
        self.guard(result)?;
        Ok(self.durable)
    }

    /// The interval policy's clock: syncs when `interval_ns` passed since
    /// the last sync and something was written since. Returns the durable
    /// position.
    ///
    /// # Errors
    ///
    /// As [`SegmentStore::sync`].
    pub fn tick(&mut self, now_ns: u64) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        // A sync since the last tick (explicit, or a roll's) restarts the
        // interval here.
        if self.synced_since_tick {
            self.synced_since_tick = false;
            self.last_sync_ns = now_ns;
        }
        if let SyncPolicy::Every { interval_ns } = self.policy
            && now_ns.saturating_sub(self.last_sync_ns) >= interval_ns
            && self.written > self.durable
        {
            self.last_sync_ns = now_ns;
            self.sync()?;
            self.synced_since_tick = false;
        }
        Ok(self.durable)
    }

    /// Closes the store, synced unless the policy is no sync, and returns
    /// the durable position.
    ///
    /// # Errors
    ///
    /// As [`SegmentStore::sync`].
    pub fn close(mut self) -> Result<u64, SegmentError> {
        if self.policy != SyncPolicy::None {
            self.sync()?;
        }
        Ok(self.durable)
    }

    /// Reads `buf.len()` bytes at `position`, within `[start, written)`.
    ///
    /// # Errors
    ///
    /// [`SegmentError::OutOfRange`], and the operating system's errors.
    pub fn read(&mut self, position: u64, buf: &mut [u8]) -> Result<(), SegmentError> {
        let length = u64::try_from(buf.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let end = position.checked_add(length);
        if position < self.start || end.is_none_or(|end| end > self.written) {
            return Err(SegmentError::OutOfRange {
                position,
                length,
                start: self.start,
                written: self.written,
            });
        }
        let mut position = position;
        let mut buf = buf;
        while !buf.is_empty() {
            let base = self.geometry.base_of(position);
            let room = base
                .checked_add(self.geometry.segment_length)
                .and_then(|end| end.checked_sub(position))
                .ok_or(SegmentError::PositionOverflow)?;
            let take = usize::try_from(room).map_or(buf.len(), |room| room.min(buf.len()));
            let (chunk, rest) = buf.split_at_mut(take);
            let offset = position - base;
            match self.current.as_ref().filter(|open| open.base == base) {
                Some(open) => self.disk.read_at(&open.data, offset, chunk)?,
                None => {
                    let path = self.dir.join(data_name(self.recording, base));
                    let file = self.disk.open(&path)?;
                    self.disk.read_at(&file, offset, chunk)?;
                }
            }
            position = position
                .checked_add(u64::try_from(take).map_err(|_| SegmentError::PositionOverflow)?)
                .ok_or(SegmentError::PositionOverflow)?;
            buf = rest;
        }
        Ok(())
    }

    /// Recovers recording `recording` in `dir` after a crash or a close:
    /// keeps every whole, checked write in order, cuts at the first that
    /// is not, removes later segments, and makes what it kept durable.
    ///
    /// # Errors
    ///
    /// [`SegmentError::NotFound`] when no segment has a valid header (the
    /// recording's creation did not complete; its files are removed), and
    /// the operating system's errors.
    pub fn recover(
        mut disk: D,
        dir: &Path,
        recording: u64,
        geometry: Geometry,
        policy: SyncPolicy,
    ) -> Result<Recovered<D>, SegmentError> {
        let bases = bases(recording, &disk.list(dir)?);
        let mut scan = Scan {
            start: None,
            written: None,
            cut: None,
            kept: None,
            dropped: 0,
        };
        let last = bases.last().copied();
        for base in bases {
            // After a cut nothing continues the recording.
            if scan.cut.is_some() {
                remove_segment(&mut disk, dir, recording, base)?;
                scan.dropped = scan.dropped.saturating_add(1);
                continue;
            }
            let is_last = Some(base) == last;
            match scan_segment(
                &mut disk, dir, recording, geometry, base, is_last, &mut scan,
            )? {
                Some(kept) => {
                    // The previous kept segment is finished; this one is the
                    // newest.
                    scan.kept = Some(kept);
                }
                None => {
                    remove_segment(&mut disk, dir, recording, base)?;
                    scan.dropped = scan.dropped.saturating_add(1);
                }
            }
        }
        let (Some(start), Some(kept)) = (scan.start, scan.kept) else {
            return Err(SegmentError::NotFound { recording });
        };
        let written = scan.written.unwrap_or(start);
        // What lies beyond the kept writes is never read; dropping it keeps
        // the file's length at its written end.
        let length = written
            .checked_sub(kept.base)
            .ok_or(SegmentError::PositionOverflow)?;
        if disk.len(&kept.data)? > length {
            disk.truncate(&kept.data, length)?;
        }
        disk.sync(&kept.data)?;
        disk.sync(&kept.index)?;
        disk.sync_dir(dir)?;
        let store = Self {
            disk,
            dir: dir.to_path_buf(),
            recording,
            geometry,
            policy,
            start,
            written,
            durable: written,
            current: Some(Open {
                base: kept.base,
                data: kept.data,
                index: kept.index,
                entries: kept.entries,
                dirty: false,
            }),
            finished: Vec::new(),
            unsynced_behind: false,
            last_sync_ns: 0,
            synced_since_tick: false,
            failed: false,
            #[cfg(test)]
            skip_index_sync: false,
        };
        Ok(Recovered {
            store,
            cut: scan.cut,
            dropped_segments: scan.dropped,
        })
    }
}

/// A segment recovery keeps.
#[derive(Debug)]
struct Kept<F> {
    base: u64,
    data: F,
    index: F,
    entries: u64,
}

/// Recovery's progress over the segments, in order.
#[derive(Debug)]
struct Scan<F> {
    start: Option<u64>,
    written: Option<u64>,
    cut: Option<Cut>,
    kept: Option<Kept<F>>,
    dropped: u32,
}

/// Removes both files of the segment at `base`, those that exist.
fn remove_segment<D: Disk>(
    disk: &mut D,
    dir: &Path,
    recording: u64,
    base: u64,
) -> Result<(), SegmentError> {
    for name in [data_name(recording, base), index_name(recording, base)] {
        match disk.remove(&dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Scans the segment at `base`: `None` when it has no valid header (its
/// creation did not complete), else the segment, with its index cut at
/// the first entry that does not hold.
#[allow(
    clippy::too_many_arguments,
    reason = "one segment of one recovery: its place and the scan's state"
)]
fn scan_segment<D: Disk>(
    disk: &mut D,
    dir: &Path,
    recording: u64,
    geometry: Geometry,
    base: u64,
    last: bool,
    scan: &mut Scan<D::File>,
) -> Result<Option<Kept<D::File>>, SegmentError> {
    let bad = |problem| SegmentError::BadHeader { base, problem };
    let data_path = dir.join(data_name(recording, base));
    let index_path = dir.join(index_name(recording, base));
    // The data file is created before the index: an index alone is never a
    // crash's leftover.
    let data = match disk.open(&data_path) {
        Ok(data) => Some(data),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let index = match disk.open(&index_path) {
        Ok(index) => Some(index),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let read = match &index {
        Some(index) => {
            let mut bytes = [0u8; 48];
            match disk.read_at(index, 0, &mut bytes) {
                Ok(()) => Header::read(Some(&bytes)),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Header::read(None),
                Err(error) => return Err(error.into()),
            }
        }
        None => HeaderRead::Missing,
    };
    // The header is durable before anything is written in the segment: a
    // header missing or torn with data or entries behind it was durable
    // once, so the segment was not being created, it is damaged.
    let empty = match (&data, &index) {
        (Some(data), Some(index)) => disk.len(data)? == 0 && disk.len(index)? <= HEADER,
        (None, Some(index)) => disk.len(index)? <= HEADER,
        (Some(data), None) => disk.len(data)? == 0,
        (None, None) => true,
    };
    let (header, data, index) = match (read, data, index) {
        (HeaderRead::Valid(header), Some(data), Some(index)) => (header, data, index),
        (HeaderRead::Valid(_), None, Some(_)) => return Err(bad(HeaderProblem::Incomplete)),
        (HeaderRead::Foreign, _, _) => return Err(bad(HeaderProblem::Foreign)),
        (HeaderRead::Torn, _, _) if !empty => return Err(bad(HeaderProblem::Corrupt)),
        (HeaderRead::Missing, _, Some(_)) if !empty => return Err(bad(HeaderProblem::Corrupt)),
        (HeaderRead::Missing, _, None) if !empty => return Err(bad(HeaderProblem::Incomplete)),
        // Only the last segment can be the one being created (at the
        // recording's start, or a roll, with nothing written in it).
        (HeaderRead::Missing | HeaderRead::Torn, _, _) if last => {
            if scan.start.is_some() && scan.written.is_some_and(|written| written != base) {
                scan.cut = Some(Cut {
                    position: scan.written.unwrap_or(base),
                    reason: CutReason::Header,
                });
            }
            return Ok(None);
        }
        _ => return Err(bad(HeaderProblem::Incomplete)),
    };
    if (
        header.recording,
        header.base,
        header.segment_length,
        header.term_length,
    ) != (
        recording,
        base,
        geometry.segment_length,
        geometry.term_length,
    ) {
        return Err(bad(HeaderProblem::Mismatch));
    }
    let segment_end = base
        .checked_add(geometry.segment_length)
        .ok_or(SegmentError::PositionOverflow)?;
    if header.start < base || header.start >= segment_end {
        return Err(bad(HeaderProblem::OutOfRange));
    }
    let segment_start = header.start;
    let next = scan.written.unwrap_or(segment_start);
    if scan.start.is_none() {
        scan.start = Some(segment_start);
    } else if segment_start != base || next != base {
        scan.cut = Some(Cut {
            position: next,
            reason: CutReason::NotContiguous,
        });
        return Ok(None);
    }
    let length = disk.len(&index)?;
    let whole = length.saturating_sub(HEADER) / ENTRY;
    let torn = length > HEADER && !(length - HEADER).is_multiple_of(ENTRY);
    let end = base
        .checked_add(geometry.segment_length)
        .ok_or(SegmentError::PositionOverflow)?;
    let mut expected_start = next;
    let mut kept = 0u64;
    let mut cut = None;
    let mut buffer = Vec::new();
    for index_entry in 0..whole {
        let at = entry_offset(index_entry).ok_or(SegmentError::PositionOverflow)?;
        let mut bytes = [0u8; 32];
        disk.read_at(&index, at, &mut bytes)?;
        let Some(entry) = Entry::decode(&bytes) else {
            cut = Some(CutReason::EntryChecksum);
            break;
        };
        let entry_end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        if entry.start != expected_start || entry_end > end || entry.length == 0 {
            cut = Some(CutReason::NotContiguous);
            break;
        }
        buffer.resize(
            usize::try_from(entry.length).map_err(|_| SegmentError::PositionOverflow)?,
            0,
        );
        let offset = entry.start - base;
        let read = disk.read_at(&data, offset, &mut buffer);
        let matches = match read {
            Ok(()) => crc32c(&buffer) == entry.data_crc,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => false,
            Err(error) => return Err(error.into()),
        };
        if !matches {
            cut = Some(CutReason::DataChecksum);
            break;
        }
        expected_start = entry_end;
        kept = index_entry.saturating_add(1);
    }
    if cut.is_none() && torn {
        cut = Some(CutReason::TornEntry);
    }
    if let Some(reason) = cut {
        let keep = entry_offset(kept).ok_or(SegmentError::PositionOverflow)?;
        disk.truncate(&index, keep)?;
        scan.cut = Some(Cut {
            position: expected_start,
            reason,
        });
    }
    scan.written = Some(expected_start);
    Ok(Some(Kept {
        base,
        data,
        index,
        entries: kept,
    }))
}
