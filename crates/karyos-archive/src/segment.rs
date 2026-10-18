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
//! - **Verification.** [`SegmentStore::verify`] reports what recovery
//!   would do, as a [`RecoveryPlan`] (the kept segment and extent, the
//!   cut, the segments removed and why), without changing anything: it
//!   lists, opens for reading and reads. `recover` applies the same scan's
//!   plan, so the two never disagree; a refusal is the same error from
//!   both.
//! - **Truncation.** [`SegmentStore::truncate`] cuts the recording at the
//!   end of a write: it syncs everything, writes an invalid entry right
//!   after the last write kept and syncs it (from then on recovery cuts
//!   there and removes every later segment unread), then shortens the
//!   data file, removes the later segments and drops the invalid entry.
//!   A crash inside recovers either as before or at the cut.
//! - **Headers.** Only the last segment can be one being created, and
//!   recovery removes it: its index header is missing, short or zeroed, or
//!   torn (failing its CRC) with no data and no entry behind it; or its
//!   header is valid with no entry and no data file, since a crash can
//!   keep the index's directory entry and lose the data file's (the
//!   creation gap). Creation makes the header durable before any write, so
//!   a torn header with data or entries behind it is corruption. Any other
//!   bad header is a typed error that removes nothing: one missing or torn
//!   before the last segment, a data file missing before the last segment
//!   or under entries, a corrupt one, one of another format version, one
//!   naming another recording or geometry, or one whose start is outside
//!   its segment.
//!
//! - **Kinds.** An index entry covers data, a fill or a gap (byte 16 of
//!   the entry; zero, data, in every entry of the first version). A fill
//!   is a padding or aborted block: its canonical 32-byte record is stored
//!   and checked, and the entry covers the block's logical extent. A gap is
//!   a range an async recording lost: nothing is stored, and a read inside
//!   it is refused. Positions stay contiguous across all three. An entry of
//!   a kind this version does not know is refused at recovery, never cut.
//! - **Record time.** Index version 2 stamps each entry with the time the
//!   Archive wrote it (bytes 20 to 27: nanoseconds of the recorder's
//!   monotonic clock, set by [`SegmentStore::stamp`]; 0 when unknown). It
//!   is the arrival cadence the recorder saw, not the publish time, and it
//!   serves only relative pacing of a replay: its origin is the Archive
//!   process, so only differences within one recording mean anything. The
//!   wall-clock start stays in the catalog.

#[cfg(test)]
mod tests;

pub mod replay;

use std::io;
use std::path::{Path, PathBuf};

pub use crate::disk::{Disk, StdDisk};

use crate::crc32c::crc32c;

/// The default segment length, where the term length divides it.
pub const DEFAULT_SEGMENT_LENGTH: u64 = 128 << 20;

/// "KYSX", the index magic.
const MAGIC: u32 = u32::from_le_bytes(*b"KYSX");
/// The index format version: 2 adds the record time of each entry.
const VERSION: u32 = 2;
/// The index header's length.
const HEADER: u64 = 48;
/// [`HEADER`] as a buffer length.
const HEADER_BYTES: usize = 48;
const _: () = assert!(HEADER == 48, "HEADER_BYTES is HEADER");
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

/// What an index entry covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Frames, stored at their positions and checked by their CRC.
    Data,
    /// A padding or aborted block: its canonical 32-byte record is stored
    /// at its position and checked, and the entry covers the block's whole
    /// logical extent, so positions stay contiguous.
    Fill,
    /// A range the recording lost (an async recording lapped): nothing is
    /// stored, and a read inside it is refused.
    Gap,
}

impl EntryKind {
    const fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Fill => 1,
            Self::Gap => 2,
        }
    }

    const fn of(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Data),
            1 => Some(Self::Fill),
            2 => Some(Self::Gap),
            _ => None,
        }
    }
}

/// The length of a fill's canonical record.
pub const FILL_RECORD: usize = 32;
/// [`FILL_RECORD`] as an entry length.
const FILL_RECORD_LEN: u32 = 32;

/// The lost ranges a store records at most; a gap past them is refused
/// ([`SegmentError::TooManyGaps`]), so the list a read checks is bounded.
pub const MAX_GAPS: usize = 1024;

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

/// Why recovery removes a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// It lies after the cut: nothing continues the recording.
    AfterCut,
    /// The last segment, being created: its index header is missing or
    /// torn, with no data and no entry behind it.
    Creating,
    /// The last segment, its creation cut short: a valid index header, no
    /// entry, and no data file (its directory entry did not survive).
    CreationGap,
    /// It does not start where the previous segment ends.
    NotContiguous,
}

/// A segment recovery removes, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DroppedSegment {
    /// The segment's base position.
    pub base: u64,
    /// Why it is removed.
    pub reason: DropReason,
}

/// The newest segment recovery keeps, and the recording's extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeptSegment {
    /// The segment's base position.
    pub base: u64,
    /// The recording's start.
    pub start: u64,
    /// The end of the last write kept: the store's `written` and
    /// `durable` after recovery.
    pub written: u64,
    /// The index entries it keeps.
    pub entries: u64,
    /// The length its index is cut to, when the cut lies in it.
    pub index_length: Option<u64>,
    /// The length its data file is shortened to, when bytes lie past
    /// `written`.
    pub data_length: Option<u64>,
}

/// What recovery does to a recording, computed by
/// [`SegmentStore::verify`] without changing anything, and applied by
/// [`SegmentStore::recover`], which is built on the same scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// The segment kept as the newest; `None` when no segment has a valid
    /// header, and recovery then removes every segment and returns
    /// [`SegmentError::NotFound`].
    pub kept: Option<KeptSegment>,
    /// Where the recording is cut, if it is.
    pub cut: Option<Cut>,
    /// The segments removed, in order.
    pub dropped: Vec<DroppedSegment>,
    gaps: Vec<(u64, u64)>,
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
    /// A fill shorter than its record, or longer than its segment's room.
    #[error("a fill of {extent} bytes does not fit")]
    InvalidFill {
        /// The fill's extent.
        extent: u32,
    },
    /// A read touches a range the recording lost.
    #[error("[{from}, {to}) was lost")]
    Gap {
        /// The lost range's start.
        from: u64,
        /// Its end.
        to: u64,
    },
    /// An index entry of a kind this version does not know (a newer
    /// format): recovery refuses it rather than cut recorded data.
    #[error("index entry at {position} has unknown kind {kind}")]
    UnknownEntryKind {
        /// The entry's position.
        position: u64,
        /// Its kind code.
        kind: u8,
    },
    /// An earlier operation failed: the store's state on disk is unknown
    /// until it is recovered.
    #[error("the store failed earlier and must be recovered")]
    Failed,
    /// The store records [`MAX_GAPS`] lost ranges already.
    #[error("more than {MAX_GAPS} lost ranges")]
    TooManyGaps,
    /// A truncation to a position outside `[start, written]`, or inside a
    /// write: nothing changed.
    #[error("cannot truncate to {position}: not a write boundary in [{start}, {written}]")]
    InvalidTruncate {
        /// The position asked.
        position: u64,
        /// The recording's first position.
        start: u64,
        /// The written position.
        written: u64,
    },
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
    /// file missing under its index, before the last segment or with
    /// entries.
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
    /// The lost ranges, in order: reads inside them are refused.
    gaps: Vec<(u64, u64)>,
    /// Finished segments the interval policy syncs at its next tick.
    finished: Vec<Open<D::File>>,
    /// The first segment finished without a sync (no-sync policy):
    /// `durable` cannot pass it until [`SegmentStore::close_synced`] syncs
    /// it and those after it.
    unsynced_behind: Option<u64>,
    last_sync_ns: u64,
    /// A sync ran since the last tick (explicit, or a roll's).
    synced_since_tick: bool,
    failed: bool,
    /// The record time stamped on the next entries ([`SegmentStore::stamp`]).
    time_ns: u64,
    /// Test only: the index is not synced (a negative control).
    #[cfg(test)]
    skip_index_sync: bool,
}

/// An index entry: its range, its kind (byte 16), the CRC of what it
/// stored and its record time (bytes 20 to 27; 0 when unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    start: u64,
    length: u32,
    data_crc: u32,
    kind: EntryKind,
    time_ns: u64,
}

/// A decoded entry, or the code of a kind this version does not know.
type Decoded = Result<Entry, (u64, u8)>;

impl Entry {
    fn encode(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        put(&mut bytes, 0, &self.start.to_le_bytes());
        put(&mut bytes, 8, &self.length.to_le_bytes());
        put(&mut bytes, 12, &self.data_crc.to_le_bytes());
        put(&mut bytes, 16, &[self.kind.code()]);
        put(&mut bytes, 20, &self.time_ns.to_le_bytes());
        let crc = crc32c(bytes.get(..28).unwrap_or_default());
        put(&mut bytes, 28, &crc.to_le_bytes());
        bytes
    }

    /// The entry in `bytes`, if its own CRC holds.
    fn decode(bytes: &[u8; 32]) -> Option<Decoded> {
        if crc32c(bytes.get(..28)?) != u32_at(bytes, 28)? {
            return None;
        }
        let start = u64_at(bytes, 0)?;
        let code = *bytes.get(16)?;
        let Some(kind) = EntryKind::of(code) else {
            return Some(Err((start, code)));
        };
        Some(Ok(Self {
            start,
            length: u32_at(bytes, 8)?,
            data_crc: u32_at(bytes, 12)?,
            kind,
            time_ns: u64_at(bytes, 20)?,
        }))
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
    fn encode(self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0u8; HEADER_BYTES];
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

    fn read(bytes: Option<&[u8; HEADER_BYTES]>) -> HeaderRead {
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

/// The geometry recording `recording`'s first segment in `dir` names in
/// its header, read only: `None` when it has no segment, or its first
/// header is missing, torn or foreign. A tool that reads a store it did
/// not create learns its geometry here, before [`SegmentStore::recover`].
///
/// # Errors
///
/// The operating system's errors.
pub fn recorded_geometry<D: Disk>(
    disk: &mut D,
    dir: &Path,
    recording: u64,
) -> Result<Option<Geometry>, SegmentError> {
    let Some(&base) = bases(recording, &disk.list(dir)?).first() else {
        return Ok(None);
    };
    let index = match disk.open_read(&dir.join(index_name(recording, base))) {
        Ok(index) => index,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = [0u8; HEADER_BYTES];
    let header = match disk.read_at(&index, 0, &mut bytes) {
        Ok(()) => Header::read(Some(&bytes)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(match header {
        HeaderRead::Valid(header) if header.recording == recording => {
            Geometry::new(header.term_length, header.segment_length).ok()
        }
        _ => None,
    })
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
            gaps: Vec::new(),
            finished: Vec::new(),
            unsynced_behind: None,
            last_sync_ns: 0,
            synced_since_tick: false,
            failed: false,
            time_ns: 0,
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

    /// Its sync policy.
    #[must_use]
    pub const fn policy(&self) -> SyncPolicy {
        self.policy
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

    /// The ranges the recording lost, in order.
    #[must_use]
    pub fn gaps(&self) -> &[(u64, u64)] {
        &self.gaps
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
        let length = u32::try_from(chunk.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let entry = Entry {
            start: self.written,
            length,
            data_crc: crc32c(chunk),
            kind: EntryKind::Data,
            time_ns: self.time_ns,
        };
        self.write_entry(entry, chunk, None)
    }

    /// Writes `stored` at the entry's position, extends the data file to
    /// `extend_to` when given, then appends the entry: the entry is last,
    /// so what it covers is in place before it counts.
    fn write_entry(
        &mut self,
        entry: Entry,
        stored: &[u8],
        extend_to: Option<u64>,
    ) -> Result<(), SegmentError> {
        let open = self.current.as_mut().ok_or(SegmentError::Failed)?;
        let offset = entry
            .start
            .checked_sub(open.base)
            .ok_or(SegmentError::PositionOverflow)?;
        let entry_at = entry_offset(open.entries).ok_or(SegmentError::PositionOverflow)?;
        if !stored.is_empty() {
            self.disk.write_at(&open.data, offset, stored)?;
        }
        if let Some(length) = extend_to
            && self.disk.len(&open.data)? < length
        {
            self.disk.set_len(&open.data, length)?;
        }
        self.disk.write_at(&open.index, entry_at, &entry.encode())?;
        open.entries = open
            .entries
            .checked_add(1)
            .ok_or(SegmentError::PositionOverflow)?;
        open.dirty = true;
        self.written = entry.end().ok_or(SegmentError::PositionOverflow)?;
        Ok(())
    }

    /// Opens the segment for the written position, if the open one ends
    /// there.
    fn segment_for_written(&mut self) -> Result<u64, SegmentError> {
        let base = self.geometry.base_of(self.written);
        if self.current.as_ref().is_none_or(|open| open.base != base) {
            self.roll(base)?;
        }
        Ok(base)
    }

    /// Appends a padding or aborted block at `position`, the written
    /// position: its canonical `record` is stored and checked, and the
    /// entry covers its logical `extent`, which stays inside one segment
    /// (a block never crosses a term end). Returns the written position.
    ///
    /// # Errors
    ///
    /// As [`SegmentStore::append`], and [`SegmentError::InvalidFill`].
    pub fn append_fill(
        &mut self,
        position: u64,
        record: &[u8; FILL_RECORD],
        extent: u32,
    ) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        if position != self.written {
            return Err(SegmentError::NotContiguous {
                expected: self.written,
                got: position,
            });
        }
        // Checked before anything is written: a refusal changes nothing.
        let base = self.geometry.base_of(self.written);
        let room = base
            .checked_add(self.geometry.segment_length)
            .and_then(|end| end.checked_sub(self.written))
            .ok_or(SegmentError::PositionOverflow)?;
        if extent < FILL_RECORD_LEN || u64::from(extent) > room {
            return Err(SegmentError::InvalidFill { extent });
        }
        let result = self.fill(record, extent);
        self.guard(result)
    }

    fn fill(&mut self, record: &[u8; FILL_RECORD], extent: u32) -> Result<u64, SegmentError> {
        let base = self.segment_for_written()?;
        let entry = Entry {
            start: self.written,
            length: extent,
            data_crc: crc32c(record),
            kind: EntryKind::Fill,
            time_ns: self.time_ns,
        };
        let end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        let extent_end = end
            .checked_sub(base)
            .ok_or(SegmentError::PositionOverflow)?;
        self.write_entry(entry, record, Some(extent_end))?;
        Ok(self.written)
    }

    /// Records the range `[position, to)` as lost: nothing is stored, and a
    /// read inside it is refused. Returns the written position, `to`.
    ///
    /// # Errors
    ///
    /// As [`SegmentStore::append`].
    pub fn append_gap(&mut self, position: u64, to: u64) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        if position != self.written {
            return Err(SegmentError::NotContiguous {
                expected: self.written,
                got: position,
            });
        }
        if to <= position {
            return Ok(self.written);
        }
        // Checked before anything is written: a refusal changes nothing.
        if !self.gap_fits() {
            return Err(SegmentError::TooManyGaps);
        }
        let result = self.gap(to);
        self.guard(result)
    }

    fn gap(&mut self, to: u64) -> Result<u64, SegmentError> {
        let from = self.written;
        while self.written < to {
            let base = self.segment_for_written()?;
            let segment_end = base
                .checked_add(self.geometry.segment_length)
                .ok_or(SegmentError::PositionOverflow)?;
            let end = to.min(segment_end);
            let length = end
                .checked_sub(self.written)
                .and_then(|length| u32::try_from(length).ok())
                .ok_or(SegmentError::PositionOverflow)?;
            let entry = Entry {
                start: self.written,
                length,
                data_crc: 0,
                kind: EntryKind::Gap,
                time_ns: self.time_ns,
            };
            self.write_entry(entry, &[], None)?;
        }
        // `append_gap` checked that it fits.
        let _ = push_gap(&mut self.gaps, from, to);
        Ok(self.written)
    }

    /// Finishes the open segment, synced unless the policy is no sync, and
    /// opens the one at `base`.
    fn roll(&mut self, base: u64) -> Result<(), SegmentError> {
        let dirty = self.current.as_ref().is_some_and(|open| open.dirty);
        match self.policy {
            SyncPolicy::None if dirty => {
                if self.unsynced_behind.is_none() {
                    self.unsynced_behind = self.current.as_ref().map(|open| open.base);
                }
            }
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
        if self.unsynced_behind.is_none() {
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
            && now_ns
                .checked_sub(self.last_sync_ns)
                .is_some_and(|elapsed| elapsed >= interval_ns)
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

    /// Closes the store with everything written durable, whatever its
    /// policy: a recording's end, whose catalog entry names the returned
    /// durable position. Segments a no-sync policy finished unsynced are
    /// opened again and synced, data then index, before the open one.
    ///
    /// # Errors
    ///
    /// As [`SegmentStore::sync`].
    pub fn close_synced(mut self) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        let result = self.sync_behind();
        self.guard(result)?;
        self.sync()?;
        Ok(self.durable)
    }

    /// Syncs the segments finished without a sync, from the first of them
    /// up to the open one.
    fn sync_behind(&mut self) -> Result<(), SegmentError> {
        let Some(mut base) = self.unsynced_behind else {
            return Ok(());
        };
        let open = self.current.as_ref().map(|open| open.base);
        while Some(base) != open && base < self.written {
            for name in [
                data_name(self.recording, base),
                index_name(self.recording, base),
            ] {
                let file = self.disk.open(&self.dir.join(name))?;
                self.disk.sync(&file)?;
            }
            base = base
                .checked_add(self.geometry.segment_length)
                .ok_or(SegmentError::PositionOverflow)?;
        }
        self.unsynced_behind = None;
        Ok(())
    }

    /// Truncates the recording to `position`, the end of a write (or the
    /// start): everything after it is removed, on disk and in the store,
    /// and what is kept is durable on return. Returns the durable
    /// position, `position`.
    ///
    /// A crash at any point inside leaves a recording that recovers either
    /// as it was or to `position`. First everything is synced, and an
    /// invalid entry is written right after the last write kept and
    /// synced: from then on recovery cuts there, and removes every later
    /// segment without reading it. Then the data file is shortened, the
    /// later segments are removed, and the invalid entry is dropped.
    ///
    /// # Errors
    ///
    /// [`SegmentError::InvalidTruncate`] for a position outside `[start,
    /// written]` or inside a write, which changes nothing;
    /// [`SegmentError::Failed`] after an earlier failure; the operating
    /// system's errors, after which the store fails until recovered.
    pub fn truncate(&mut self, position: u64) -> Result<u64, SegmentError> {
        if self.failed {
            return Err(SegmentError::Failed);
        }
        let invalid = SegmentError::InvalidTruncate {
            position,
            start: self.start,
            written: self.written,
        };
        if position < self.start || position > self.written {
            return Err(invalid);
        }
        // The segment that keeps the last write: at a segment's end, the
        // one it ends; at the start, the first.
        let segment_length = self.geometry.segment_length;
        let base = if position > self.start && position.is_multiple_of(segment_length) {
            position
                .checked_sub(segment_length)
                .ok_or(SegmentError::PositionOverflow)?
        } else {
            self.geometry.base_of(position)
        };
        let result = self.boundary(base, position);
        let entries = match self.guard(result)? {
            Some(entries) => entries,
            None => return Err(invalid),
        };
        let result = self.cut(base, entries, position);
        self.guard(result)?;
        Ok(self.durable)
    }

    /// The number of entries of the segment at `base` that end at
    /// `position`; `None` when no write ends there.
    fn boundary(&mut self, base: u64, position: u64) -> Result<Option<u64>, SegmentError> {
        let index = self
            .disk
            .open(&self.dir.join(index_name(self.recording, base)))?;
        let mut header = [0u8; HEADER_BYTES];
        self.disk.read_at(&index, 0, &mut header)?;
        let HeaderRead::Valid(header) = Header::read(Some(&header)) else {
            return Err(SegmentError::BadHeader {
                base,
                problem: HeaderProblem::Corrupt,
            });
        };
        let mut at = header.start;
        let mut entries = 0u64;
        let length = self.disk.len(&index)?;
        while at < position {
            let offset = entry_offset(entries).ok_or(SegmentError::PositionOverflow)?;
            if offset >= length {
                return Ok(None);
            }
            let mut bytes = [0u8; 32];
            self.disk.read_at(&index, offset, &mut bytes)?;
            let Some(Ok(entry)) = Entry::decode(&bytes) else {
                return Ok(None);
            };
            at = entry.end().ok_or(SegmentError::PositionOverflow)?;
            entries = entries
                .checked_add(1)
                .ok_or(SegmentError::PositionOverflow)?;
        }
        Ok((at == position).then_some(entries))
    }

    /// Cuts the recording after the first `entries` entries of the segment
    /// at `base`, which end at `position` (see [`SegmentStore::truncate`]
    /// for the order).
    fn cut(&mut self, base: u64, entries: u64, position: u64) -> Result<(), SegmentError> {
        self.sync_behind()?;
        self.sync_open()?;
        let index_path = self.dir.join(index_name(self.recording, base));
        let data_path = self.dir.join(data_name(self.recording, base));
        let index = self.disk.open(&index_path)?;
        let data = self.disk.open(&data_path)?;
        // From here a crash may recover to `position`: nothing past it is
        // claimed written or durable any more.
        self.written = position;
        self.durable = self.durable.min(position);
        // The invalid entry: its own CRC fails, so recovery cuts there.
        let keep = entry_offset(entries).ok_or(SegmentError::PositionOverflow)?;
        let terminator = entry_offset(
            entries
                .checked_add(1)
                .ok_or(SegmentError::PositionOverflow)?,
        )
        .ok_or(SegmentError::PositionOverflow)?;
        self.disk.write_at(&index, keep, &[0u8; 32])?;
        self.disk.set_len(&index, terminator)?;
        self.disk.sync(&index)?;
        let length = position
            .checked_sub(base)
            .ok_or(SegmentError::PositionOverflow)?;
        self.disk.set_len(&data, length)?;
        self.disk.sync(&data)?;
        // The open and finished segments go before their files do.
        self.current = None;
        self.finished.clear();
        for later in bases(self.recording, &self.disk.list(&self.dir)?)
            .into_iter()
            .filter(|later| *later > base)
            .rev()
        {
            remove_segment(&mut self.disk, &self.dir, self.recording, later)?;
        }
        self.disk.sync_dir(&self.dir)?;
        self.disk.set_len(&index, keep)?;
        self.disk.sync(&index)?;
        self.gaps.retain(|(from, _)| *from < position);
        self.written = position;
        self.durable = position;
        self.unsynced_behind = None;
        self.current = Some(Open {
            base,
            data,
            index,
            entries,
            dirty: false,
        });
        Ok(())
    }

    /// Whether the store records a gap at the written position: it merges
    /// with the last one, or fewer than [`MAX_GAPS`] are recorded.
    #[must_use]
    pub fn gap_fits(&self) -> bool {
        self.gaps.len() < MAX_GAPS || self.gaps.last().is_some_and(|last| last.1 == self.written)
    }

    /// Sets the record time stamped on the entries written next: the
    /// recorder's monotonic clock in nanoseconds. 0 means unknown, so a
    /// time of 0 is stamped as 1.
    pub fn stamp(&mut self, now_ns: u64) {
        self.time_ns = now_ns.max(1);
    }

    /// Reads `buf.len()` bytes at `position`, within `[start, written)`.
    ///
    /// # Errors
    ///
    /// [`SegmentError::OutOfRange`], and the operating system's errors.
    pub fn read(&mut self, position: u64, buf: &mut [u8]) -> Result<(), SegmentError> {
        let length = u64::try_from(buf.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let end = position.checked_add(length);
        let Some(end) = end.filter(|end| position >= self.start && *end <= self.written) else {
            return Err(SegmentError::OutOfRange {
                position,
                length,
                start: self.start,
                written: self.written,
            });
        };
        if let Some(&(from, to)) = self
            .gaps
            .iter()
            .find(|(from, to)| *from < end && position < *to)
        {
            return Err(SegmentError::Gap { from, to });
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
            let offset = position
                .checked_sub(base)
                .ok_or(SegmentError::PositionOverflow)?;
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
    /// is not, removes later segments, and makes what it kept durable. It
    /// applies the plan [`SegmentStore::verify`] reports.
    ///
    /// # Errors
    ///
    /// [`SegmentError::NotFound`] when no segment has a valid header (the
    /// recording's creation did not complete; its files are removed),
    /// [`SegmentError::BadHeader`] and the other refusals of
    /// [`SegmentStore::verify`], which remove nothing, and the operating
    /// system's errors.
    pub fn recover(
        mut disk: D,
        dir: &Path,
        recording: u64,
        geometry: Geometry,
        policy: SyncPolicy,
    ) -> Result<Recovered<D>, SegmentError> {
        let (plan, files) = scan_recording(&mut disk, dir, recording, geometry, Access::Write)?;
        if let (Some(kept), Some((_, index))) = (plan.kept, &files)
            && let Some(length) = kept.index_length
        {
            disk.set_len(index, length)?;
        }
        for dropped in &plan.dropped {
            remove_segment(&mut disk, dir, recording, dropped.base)?;
        }
        let (Some(kept), Some((data, index))) = (plan.kept, files) else {
            return Err(SegmentError::NotFound { recording });
        };
        // What lies beyond the kept writes is never read; dropping it keeps
        // the file's length at its written end.
        if let Some(length) = kept.data_length {
            disk.set_len(&data, length)?;
        }
        disk.sync(&data)?;
        disk.sync(&index)?;
        disk.sync_dir(dir)?;
        let store = Self {
            disk,
            dir: dir.to_path_buf(),
            recording,
            geometry,
            policy,
            start: kept.start,
            written: kept.written,
            durable: kept.written,
            current: Some(Open {
                base: kept.base,
                data,
                index,
                entries: kept.entries,
                dirty: false,
            }),
            gaps: plan.gaps,
            finished: Vec::new(),
            unsynced_behind: None,
            last_sync_ns: 0,
            synced_since_tick: false,
            failed: false,
            time_ns: 0,
            #[cfg(test)]
            skip_index_sync: false,
        };
        Ok(Recovered {
            store,
            cut: plan.cut,
            dropped_segments: u32::try_from(plan.dropped.len())
                .map_err(|_| SegmentError::PositionOverflow)?,
        })
    }

    /// Reports what [`SegmentStore::recover`] would do to recording
    /// `recording` in `dir`, changing nothing: it only lists the directory,
    /// opens files for reading and reads them, so it runs on a read-only
    /// directory too. `recover` applies the same scan, so the two agree.
    ///
    /// # Errors
    ///
    /// The refusals of [`SegmentStore::recover`] other than
    /// [`SegmentError::NotFound`], which is a plan with no kept segment,
    /// and the operating system's errors.
    pub fn verify(
        mut disk: D,
        dir: &Path,
        recording: u64,
        geometry: Geometry,
    ) -> Result<RecoveryPlan, SegmentError> {
        scan_recording(&mut disk, dir, recording, geometry, Access::Read).map(|(plan, _)| plan)
    }
}

/// How a scan opens the files it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// For reading only: a verification.
    Read,
    /// For reading and writing: a recovery, which then applies the plan.
    Write,
}

/// The kept segment's data and index files.
type KeptFiles<D> = (<D as Disk>::File, <D as Disk>::File);

/// Scans recording `recording`'s segments in order, changing nothing:
/// the plan, and the kept segment's data and index files.
fn scan_recording<D: Disk>(
    disk: &mut D,
    dir: &Path,
    recording: u64,
    geometry: Geometry,
    access: Access,
) -> Result<(RecoveryPlan, Option<KeptFiles<D>>), SegmentError> {
    let bases = bases(recording, &disk.list(dir)?);
    let mut scan = Scan {
        start: None,
        written: None,
        cut: None,
        kept: None,
        dropped: Vec::new(),
        gaps: Vec::new(),
    };
    let last = bases.last().copied();
    for base in bases {
        // After a cut nothing continues the recording.
        if scan.cut.is_some() {
            scan.dropped.push(DroppedSegment {
                base,
                reason: DropReason::AfterCut,
            });
            continue;
        }
        let is_last = Some(base) == last;
        match scan_segment(
            disk, dir, recording, geometry, base, is_last, access, &mut scan,
        )? {
            // The previous kept segment is finished; this one is the newest.
            Ok(kept) => scan.kept = Some(kept),
            Err(reason) => scan.dropped.push(DroppedSegment { base, reason }),
        }
    }
    let (kept, files) = match (scan.start, scan.kept) {
        (Some(start), Some(kept)) => {
            let written = scan.written.unwrap_or(start);
            let length = written
                .checked_sub(kept.base)
                .ok_or(SegmentError::PositionOverflow)?;
            let data_length = (disk.len(&kept.data)? > length).then_some(length);
            (
                Some(KeptSegment {
                    base: kept.base,
                    start,
                    written,
                    entries: kept.entries,
                    index_length: kept.index_length,
                    data_length,
                }),
                Some((kept.data, kept.index)),
            )
        }
        _ => (None, None),
    };
    Ok((
        RecoveryPlan {
            kept,
            cut: scan.cut,
            dropped: scan.dropped,
            gaps: scan.gaps,
        },
        files,
    ))
}

/// A segment recovery keeps.
#[derive(Debug)]
struct Kept<F> {
    base: u64,
    data: F,
    index: F,
    entries: u64,
    /// The length its index is cut to, when the cut lies in it.
    index_length: Option<u64>,
}

/// Recovery's progress over the segments, in order.
#[derive(Debug)]
struct Scan<F> {
    start: Option<u64>,
    written: Option<u64>,
    cut: Option<Cut>,
    kept: Option<Kept<F>>,
    dropped: Vec<DroppedSegment>,
    gaps: Vec<(u64, u64)>,
}

/// Adds the lost range `[from, to)` to `gaps`, joining it to the last one
/// when they touch; `false`, with nothing added, past [`MAX_GAPS`].
fn push_gap(gaps: &mut Vec<(u64, u64)>, from: u64, to: u64) -> bool {
    let full = gaps.len() >= MAX_GAPS;
    match gaps.last_mut() {
        Some(last) if last.1 == from => last.1 = to,
        _ if full => return false,
        _ => gaps.push((from, to)),
    }
    true
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

/// Scans the segment at `base`, changing nothing: why it is removed, or
/// the segment, with where its index is cut at the first entry that does
/// not hold.
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
    access: Access,
    scan: &mut Scan<D::File>,
) -> Result<Result<Kept<D::File>, DropReason>, SegmentError> {
    let bad = |problem| SegmentError::BadHeader { base, problem };
    let data_path = dir.join(data_name(recording, base));
    let index_path = dir.join(index_name(recording, base));
    // The data file is created before the index, but a crash can keep the
    // index's directory entry and lose the data file's: on the last
    // segment with no entry, that is a creation cut short.
    let open = |disk: &mut D, path: &Path| match access {
        Access::Read => disk.open_read(path),
        Access::Write => disk.open(path),
    };
    let data = match open(disk, &data_path) {
        Ok(data) => Some(data),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let index = match open(disk, &index_path) {
        Ok(index) => Some(index),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let read = match &index {
        Some(index) => {
            let mut bytes = [0u8; HEADER_BYTES];
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
        // A creation cut short: the index's directory entry survived the
        // crash, the data file's did not, and nothing was written. Only
        // the last segment can be one; elsewhere the data file was lost.
        (HeaderRead::Valid(_), None, Some(_)) if last && empty => {
            if scan.start.is_some() && scan.written.is_some_and(|written| written != base) {
                scan.cut = Some(Cut {
                    position: scan.written.unwrap_or(base),
                    reason: CutReason::NotContiguous,
                });
            }
            return Ok(Err(DropReason::CreationGap));
        }
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
            return Ok(Err(DropReason::Creating));
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
        return Ok(Err(DropReason::NotContiguous));
    }
    let length = disk.len(&index)?;
    // An index shorter than its header holds no entry.
    let whole = length
        .checked_sub(HEADER)
        .map_or(0, |entries| entries / ENTRY);
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
        let Some(decoded) = Entry::decode(&bytes) else {
            cut = Some(CutReason::EntryChecksum);
            break;
        };
        let entry = decoded
            .map_err(|(position, kind)| SegmentError::UnknownEntryKind { position, kind })?;
        let entry_end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        if entry.start != expected_start || entry_end > end || entry.length == 0 {
            cut = Some(CutReason::NotContiguous);
            break;
        }
        let offset = entry
            .start
            .checked_sub(base)
            .ok_or(SegmentError::PositionOverflow)?;
        let stored = match entry.kind {
            EntryKind::Data => entry.length,
            EntryKind::Fill if entry.length >= FILL_RECORD_LEN => FILL_RECORD_LEN,
            EntryKind::Fill => {
                cut = Some(CutReason::NotContiguous);
                break;
            }
            EntryKind::Gap => 0,
        };
        if stored > 0 {
            buffer.resize(
                usize::try_from(stored).map_err(|_| SegmentError::PositionOverflow)?,
                0,
            );
            let read = disk.read_at(&data, offset, &mut buffer);
            let mut matches = match read {
                Ok(()) => crc32c(&buffer) == entry.data_crc,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => false,
                Err(error) => return Err(error.into()),
            };
            // A fill's extent is in the file before its entry.
            let extent_end = entry_end
                .checked_sub(base)
                .ok_or(SegmentError::PositionOverflow)?;
            if entry.kind == EntryKind::Fill && disk.len(&data)? < extent_end {
                matches = false;
            }
            if !matches {
                cut = Some(CutReason::DataChecksum);
                break;
            }
        }
        // Only a crafted index holds more gaps than a store records.
        if entry.kind == EntryKind::Gap && !push_gap(&mut scan.gaps, entry.start, entry_end) {
            return Err(SegmentError::TooManyGaps);
        }
        expected_start = entry_end;
        kept = index_entry
            .checked_add(1)
            .ok_or(SegmentError::PositionOverflow)?;
    }
    if cut.is_none() && torn {
        cut = Some(CutReason::TornEntry);
    }
    let mut index_length = None;
    if let Some(reason) = cut {
        index_length = Some(entry_offset(kept).ok_or(SegmentError::PositionOverflow)?);
        scan.cut = Some(Cut {
            position: expected_start,
            reason,
        });
    }
    scan.written = Some(expected_start);
    Ok(Ok(Kept {
        base,
        data,
        index,
        entries: kept,
        index_length,
    }))
}
