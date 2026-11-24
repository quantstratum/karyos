// SPDX-License-Identifier: Apache-2.0

//! The durable Raft log and its term and vote store (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C4), core neutral, over the
//! Archive's segment store (A2).
//!
//! - **Frames.** Each entry is one A2 write, so every entry starts at a
//!   write boundary and a suffix can be cut there: a 36-byte header
//!   (magic `KRLE`, payload length, index, term, event time, CRC-32C of
//!   the header's first 32 bytes and the payload), then the payload. A2
//!   splits a write only at a segment's end.
//! - **Index.** The entry-to-byte index is kept in memory and rebuilt at
//!   [`RaftLog::open`] from the frames: there is no index file.
//! - **Indices.** Any first index is valid, 0 included;
//!   [`RaftLog::last_index`] is `None` while the log is empty.
//! - **Positions** (SPEC §9, the five positions). `written` and `durable`
//!   are A2's, and their last entries are [`RaftLog::last_index`] and
//!   [`RaftLog::durable_index`]; [`RaftLog::append`] advances only the
//!   first, [`RaftLog::sync`] the second. The received position is the
//!   transport's: the log never holds an entry it was not given whole.
//!   Commit and applied are the caller's (a stored commit is checked,
//!   below).
//! - **Watermark.** [`RaftLog::sync`] records the durable last index it
//!   reports in a two-slot file ([`crate::mark`]), after A2's sync and
//!   before it returns, and a truncation lowers it before A2 cuts.
//!   [`RaftLog::durable_index`] never passes it.
//! - **Recovery.** A crash may lose any number of writes past the last
//!   sync, in any order; what a sync reported durable it must not lose.
//!   [`RaftLog::open`] loads the hard state and the watermark (a first-index
//!   file without a valid slot beside it is [`LogError::Mark`]), then asks
//!   A2 for its recovery plan ([`SegmentStore::verify`], read-only) and
//!   walks the frames the plan keeps, before anything is cut. A log that
//!   would end below the watermark is [`LogError::Corruption`]; anything
//!   lost above it is a crash's loss, accepted. [`Opened::cut`] reports
//!   the cuts recovery makes, not writes whose index entries never
//!   reached the disk. The
//!   last write may hold the first chunks of a frame whose later chunks
//!   were lost with the next segment: that torn tail is cut, unless it is
//!   committed or below the watermark. Any other frame that is not the
//!   next one is [`LogError::Chain`]: a foreign magic, a CRC failure, a
//!   length past the end, an index that does not follow, a term that goes
//!   back. Only once all that passed does A2 apply its plan and the log cut
//!   its torn tail.
//! - **Hard state.** [`HardState`] lives in its own file, replaced
//!   atomically; its stored commit only moves forward and never past the
//!   durable last index, and no committed entry is ever truncated.
//! - **Poison.** Every failed write or sync (an append's segment roll, a
//!   truncation's, a sync, a hard-state save) poisons the log: writes are
//!   refused until it is reopened, and the index keeps only what A2 still
//!   holds.
//! - **First index.** Kept in its own file, written atomically before the
//!   store at creation, so an emptied log keeps it and a creation cut
//!   short is finished at open. A prefix purge rewrites it after A2's
//!   floor (below).
//! - **Purge** (C8b). [`RaftLog::purge_prefix`] drops committed entries
//!   below an index: A2 moves the recording's start to the first kept
//!   frame, publishing it in its floor record, and removes the whole
//!   segments below; then the first-index file is replaced. A crash
//!   between the two leaves the file below the first frame, and
//!   [`RaftLog::open`] takes the first frame's index, then rewrites it.
//! - **Install** (W5; karyos#687, decided 2026-10-30 by QS-COORDINATOR).
//!   [`RaftLog::install`] restarts the log after a snapshot the node's
//!   snapshot store already holds verified: the first-index file names the
//!   next index and the base term in one record, then the watermark is
//!   cleared, A2 cuts every frame, and the commit becomes the base.
//!   [`RaftLog::open_with`] opens such a log only over its verified
//!   snapshot, and finishes an install a crash cut short; without it, the
//!   open is [`LogError::InstallUnverified`]. A later purge's plain record
//!   ends the install's base.
//! - **Allocation.** An append encodes each frame into a new `Vec`; C5's
//!   zero-allocation gate will need it reused.
//!
//! Crash cases for C2's simulated disk (not run here, since the Archive
//! has no public faulty disk):
//!
//! 1. a crash inside an append, before and after A2 indexes each chunk of
//!    an entry that spans two segments: the entry is kept whole or cut;
//! 2. a crash between `append` and `sync`: every durable entry is kept, and
//!    nothing after the last whole one;
//! 3. a crash at every step of `truncate_suffix` (A2's truncation): the
//!    log recovers as before or at the cut;
//! 4. a crash at every step of a hard-state save (temporary file write,
//!    its sync, the rename, the directory sync): the old state or the new
//!    one, never a mix;
//! 5. a torn hard-state record (a short or reordered write): refused;
//! 6. a failed flush of the log or of the hard state: the call fails, and
//!    every later write is refused until the log is reopened;
//! 7. a crash after a save whose commit was checked against the durable
//!    index: the reopened commit is never above the recovered log;
//! 8. a crash inside `create`: the reopened directory opens empty or is
//!    created again.
//! 9. a crash inside a watermark update, in a sync or a truncation: the
//!    older slot holds, and no reported durable entry is lost.

use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

use karyos_archive::control::HoldState;
use karyos_archive::crc32c::{Crc32c, crc32c};
use karyos_archive::disk::{Disk, ReadOnly};
use karyos_archive::integrity::damage::{ShortenedIndex, shortened_below_seal};
use karyos_archive::integrity::journal::{
    IntegrityError, IntegrityJournal, JOURNAL_FILE, read_records,
};
use karyos_archive::integrity::{SealKind, SealRecord, digest};
use karyos_archive::segment::{DropReason, Geometry, SegmentError, SegmentStore, SyncPolicy};

use crate::file::{self, Read};
use crate::hard_state::{HARD_STATE_FILE, HARD_STATE_LEN, HardState, HardStateProblem};
use crate::mark::{self, MARK_FILE, MARK_LEN, Slot};
use crate::snapshot::SnapshotStore;

mod mapping;

pub use mapping::{EntryAnswer, EntrySlot, SlotAnswer};

/// The A2 recording id of the log.
pub const LOG_RECORDING: u64 = 1;

/// Where the log reads the Archive's hold on its recording
/// ([`LOG_RECORDING`]) from: A10's `Retention`, or a fixed state (a node
/// with no Archive attached holds nothing: [`HoldState::None`]).
///
/// The log reads it right before each operation that removes committed
/// bytes ([`RaftLog::purge_prefix_under`], [`RaftLog::install_under`]),
/// never from a value cached across calls. Applying a hold and such an
/// operation must not interleave: the node runs both on its one thread,
/// as the harness does, so a hold applied before the read inhibits, and
/// one applied after it finds the operation done.
pub trait HoldSource {
    /// The hold state on the log's recording; [`HoldState::Unknown`] when
    /// it cannot be read.
    fn hold_state(&self) -> HoldState;
}

impl HoldSource for HoldState {
    fn hold_state(&self) -> HoldState {
        *self
    }
}

impl<J: karyos_archive::integrity::retention::OperationsJournal, E: Disk> HoldSource
    for karyos_archive::integrity::retention::Retention<J, E>
{
    fn hold_state(&self) -> HoldState {
        Self::hold_state(self, LOG_RECORDING)
    }
}
/// The most bytes one seal of the committed log reads at a time, and the
/// committed bytes a commit advance waits for before it seals: the
/// journal holds one record per chunk of committed log, not one per
/// commit advance (karyos#1050). Up to one chunk of committed tail stays
/// unsealed between seals; [`RaftLog::seal`] seals it, and a purge does
/// before it removes anything.
pub const SEAL_CHUNK: u64 = 1 << 20;
/// How long a committed tail shorter than [`SEAL_CHUNK`] may stay
/// unsealed by default before [`RaftLog::tick`] seals it: 1 s of the
/// caller's clock (karyos#1050 review).
pub const DEFAULT_SEAL_INTERVAL_NS: u64 = 1_000_000_000;
/// The file keeping where the log began and the last snapshot it
/// installed: the boundaries the entry mapping tells apart from a purge
/// (R-CORE-8, karyos#745).
pub const ORIGIN_FILE: &str = "log-origin";
/// The origin record: the creation index, the installed snapshot's base
/// index (`u64::MAX` for none), then their CRC-32C.
const ORIGIN_LEN: usize = 20;

/// The file keeping the log's first index.
pub const FIRST_INDEX_FILE: &str = "first-index";
/// A frame's header length.
pub const FRAME_HEADER: usize = 36;
/// [`FRAME_HEADER`] as a position.
pub const FRAME_HEADER_LEN: u64 = 36;
const MAGIC: [u8; 4] = *b"KRLE";
/// A new watermark file's mark: slot 0, sequence 1, unset.
const CREATED: (usize, Slot) = (
    0,
    Slot {
        sequence: 1,
        durable: None,
    },
);
/// The first-index record: the index, then its CRC-32C.
const FIRST_LEN: usize = 12;
/// The first-index record after an install: the index, the base term (of
/// the entry before it), then their CRC-32C.
const INSTALLED_LEN: usize = 20;

/// One log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its index.
    pub index: u64,
    /// The term it was created in.
    pub term: u64,
    /// The leader's event time, in its own clock's nanoseconds.
    pub event_time: u64,
    /// The command.
    pub payload: Vec<u8>,
}

impl Entry {
    /// The entry's frame: its header, then its payload.
    ///
    /// # Errors
    ///
    /// [`LogError::TooLarge`] for a payload over `u32::MAX` bytes.
    pub fn frame(&self) -> Result<Vec<u8>, LogError> {
        let length = u32::try_from(self.payload.len())
            .map_err(|_| LogError::TooLarge { index: self.index })?;
        let mut frame =
            Vec::with_capacity(self.payload.len().checked_add(FRAME_HEADER).unwrap_or(0));
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&self.index.to_le_bytes());
        frame.extend_from_slice(&self.term.to_le_bytes());
        frame.extend_from_slice(&self.event_time.to_le_bytes());
        let mut crc = Crc32c::new();
        crc.update(&frame);
        crc.update(&self.payload);
        frame.extend_from_slice(&crc.finish().to_le_bytes());
        frame.extend_from_slice(&self.payload);
        Ok(frame)
    }

    /// Its encoded size: header and payload; `None` past `u64::MAX`.
    #[must_use]
    pub fn encoded_len(&self) -> Option<u64> {
        u64::try_from(self.payload.len())
            .ok()?
            .checked_add(FRAME_HEADER_LEN)
    }
}

/// What a frame's header says.
struct Header {
    length: u32,
    index: u64,
    term: u64,
    event_time: u64,
    crc: u32,
}

impl Header {
    fn decode(bytes: &[u8; FRAME_HEADER]) -> Option<Self> {
        let (magic, rest) = bytes.split_first_chunk::<4>()?;
        let (length, rest) = rest.split_first_chunk::<4>()?;
        let (index, rest) = rest.split_first_chunk::<8>()?;
        let (term, rest) = rest.split_first_chunk::<8>()?;
        let (event_time, rest) = rest.split_first_chunk::<8>()?;
        let (crc, _) = rest.split_first_chunk::<4>()?;
        (*magic == MAGIC).then(|| Self {
            length: u32::from_le_bytes(*length),
            index: u64::from_le_bytes(*index),
            term: u64::from_le_bytes(*term),
            event_time: u64::from_le_bytes(*event_time),
            crc: u32::from_le_bytes(*crc),
        })
    }

    /// The frame's end, from its start.
    fn end(&self, start: u64) -> Option<u64> {
        start
            .checked_add(FRAME_HEADER_LEN)?
            .checked_add(u64::from(self.length))
    }
}

/// Why the log refuses an operation, or its files.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LogError {
    /// An append that does not start right after the last index.
    #[error("an append at index {got}; the next index is {expected}")]
    NotNext {
        /// The index it must start at.
        expected: u64,
        /// The index it started at.
        got: u64,
    },
    /// An append whose term is below the last entry's.
    #[error("entry {index} has term {got}, below the last term {last}")]
    TermBack {
        /// The entry's index.
        index: u64,
        /// The last term.
        last: u64,
        /// The entry's term.
        got: u64,
    },
    /// A payload over `u32::MAX` bytes, or an index past `u64::MAX`.
    #[error("entry {index} is too large")]
    TooLarge {
        /// The entry's index.
        index: u64,
    },
    /// A truncation outside `[first_index, last_index + 1]`.
    #[error("index {index} is outside the log from {first} to {last:?}")]
    OutOfRange {
        /// The index asked for.
        index: u64,
        /// The first index.
        first: u64,
        /// The last index, if any.
        last: Option<u64>,
    },
    /// A prefix purge past the stored commit: only committed entries,
    /// which a snapshot covers, are purged.
    #[error("purging below {below} would remove entries past the commit {commit:?}")]
    PurgeBeyondCommit {
        /// The first index asked to keep.
        below: u64,
        /// The stored commit.
        commit: Option<u64>,
    },
    /// An install, or an open after one, without a verified snapshot at
    /// its base durable in the snapshot store: the state up to the base
    /// would exist nowhere.
    #[error("no verified snapshot at index {index}, term {term}")]
    InstallUnverified {
        /// The base index.
        index: u64,
        /// The base term.
        term: u64,
    },
    /// An install whose base is not past the stored commit: a snapshot
    /// installs only what the log does not already hold committed.
    #[error("installing at {index} would not move past the commit {commit:?}")]
    InstallStale {
        /// The base index.
        index: u64,
        /// The stored commit.
        commit: Option<u64>,
    },
    /// A prefix purge or an install while the Archive holds the log's
    /// recording ([`LOG_RECORDING`]) under a legal hold, or cannot tell
    /// whether it does, or an open that would finish one a crash cut short
    /// (a purge's segments below A2's floor, an install's frames below its
    /// first index): snapshot install and compaction never purge through
    /// an Archive hold (owner decisions 2026-10-21, item 35; SPEC §8.4),
    /// and a crash between the intent and the deletion does not complete
    /// it once a hold applies (A10's inhibiting direction). It fails
    /// closed, as A10 does: a pending hold and an unknown hold state refuse
    /// as an applied hold does. Nothing changes, on disk or in the log.
    #[error("the Archive's hold on the log ({state:?}) forbids removing its entries")]
    ArchiveHeld {
        /// The Archive's hold state on the log's recording.
        state: HoldState,
    },
    /// A truncation that would remove an entry at or below the stored
    /// commit: committed entries are never removed.
    #[error("truncating from {from} would remove committed entries up to {commit}")]
    TruncateBelowCommit {
        /// The first index the truncation would remove.
        from: u64,
        /// The stored commit.
        commit: u64,
    },
    /// A torn tail at recovery that would remove a committed entry.
    #[error("the torn entry {index} is at or below the stored commit {commit}")]
    TornBelowCommit {
        /// The torn entry's index.
        index: u64,
        /// The stored commit.
        commit: u64,
    },
    /// A frame found at recovery that does not continue the chain.
    #[error("the frame at {position} breaks the chain: {problem:?}")]
    Chain {
        /// The frame's position.
        position: u64,
        /// What is wrong.
        problem: ChainProblem,
    },
    /// A recovery would lose entries reported durable.
    #[error("the log is corrupt: {0:?}")]
    Corruption(Corruption),
    /// [`RaftLog::create`] found a log, or what is left of one.
    #[error("a log, or what is left of one, is already there")]
    Exists,
    /// The first-index file is missing or not one this version wrote.
    #[error("the first-index file is missing or invalid")]
    FirstIndex,
    /// The durable watermark has no valid slot beside a first-index file.
    #[error("the durable watermark has no valid slot")]
    Mark,
    /// The hard-state record is refused.
    #[error("the hard state is refused: {0}")]
    HardState(HardStateProblem),
    /// A commit index above the durable last index.
    #[error("commit {commit} is above the durable last index {durable:?}")]
    CommitBeyondDurable {
        /// The commit asked for.
        commit: u64,
        /// The durable last index, if any.
        durable: Option<u64>,
    },
    /// A save whose commit is below the stored one, or none after one.
    #[error("commit {got:?} would go back from the stored {stored}")]
    CommitBack {
        /// The stored commit.
        stored: u64,
        /// The commit asked for.
        got: Option<u64>,
    },
    /// A write or a sync failed earlier: writes are refused until the log
    /// is reopened.
    #[error("a write or a sync failed: reopen the log")]
    Poisoned,
    /// The segment store's error.
    #[error(transparent)]
    Store(#[from] SegmentError),
    /// The integrity journal's error (karyos#990).
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// The recovered log ends below what its seals cover: committed,
    /// sealed bytes were lost to media damage, never an unacknowledged
    /// write (karyos#990). Nothing was written.
    #[error(
        "the log ends at {} below its seals: [{}, {}) lost, from seal {}",
        .0.written, .0.written, .0.sealed_end, .0.counter
    )]
    ShortenedBelowSeal(ShortenedIndex),
    /// The disk's error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What is wrong with a frame, at recovery or at a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProblem {
    /// Not a frame: another magic.
    Foreign,
    /// Its CRC does not match.
    Checksum,
    /// It runs past the log's end, and is not the torn last write.
    PastEnd,
    /// Its index is not the next one.
    Index {
        /// The next index.
        expected: u64,
        /// The frame's index.
        got: u64,
    },
    /// Its term is below the previous entry's.
    TermBack {
        /// The previous term.
        last: u64,
        /// The frame's term.
        got: u64,
    },
    /// At a read: its header and payload are not the bytes its index
    /// entry spans, or for the last entry run past the written end
    /// (karyos#904).
    Length {
        /// The bytes the index gives it.
        span: u64,
        /// The bytes its header claims, header included.
        claimed: u64,
    },
    /// At a read: its term is not the one the index holds (karyos#904).
    Term {
        /// The indexed term.
        expected: u64,
        /// The frame's term.
        got: u64,
    },
}

/// What a recovery would lose that was reported durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corruption {
    /// The recovered log ends below the durable watermark ([`crate::mark`]):
    /// entries [`RaftLog::sync`] reported durable are gone.
    BelowMark {
        /// The recovered last index, if any.
        last: Option<u64>,
        /// The watermark.
        mark: u64,
    },
    /// A segment's index header is bad where A2 cannot take it for one
    /// being created: a segment was lost or damaged.
    Segment {
        /// The segment's base.
        base: u64,
    },
}

/// The durable Raft log of one node, in one directory.
#[derive(Debug)]
pub struct RaftLog<D: Disk + Clone> {
    store: SegmentStore<D>,
    disk: D,
    dir: PathBuf,
    first_index: u64,
    /// Per entry from `first_index`: its frame's position and its term.
    entries: Vec<(u64, u64)>,
    /// The term of entry `first_index - 1` after an install, which only a
    /// snapshot holds.
    base_term: Option<u64>,
    /// The index the log was created at, when its origin file holds it:
    /// below it the recording never held an entry.
    origin: Option<u64>,
    /// The base of the last snapshot installed, kept across purges.
    snapshot_base: Option<u64>,
    hard_state: Option<HardState>,
    poisoned: bool,
    /// The watermark's file, its newest slot and the mark it holds.
    mark_file: D::File,
    mark_slot: usize,
    mark: Slot,
    /// The integrity journal sealing the committed log (karyos#990).
    integrity: IntegrityJournal<D>,
    /// The seal subject of the log's bytes since its last install: each
    /// install starts the next one, since it cuts sealed bytes.
    epoch: u64,
    /// The bytes of one seal, reused.
    seal_buf: Vec<u8>,
    /// The longest a committed tail waits unsealed ([`RaftLog::tick`]).
    seal_interval_ns: u64,
    /// When [`RaftLog::tick`] first saw the current unsealed tail.
    tail_since: Option<u64>,
}

/// The seal subject the log's latest cluster log record names: 0 before
/// any.
fn current_epoch(records: &[SealRecord]) -> u64 {
    records
        .iter()
        .rev()
        .find(|record| record.kind == SealKind::ClusterLog)
        .map_or(0, |record| record.subject)
}

/// The integrity journal in `dir` and the current seal subject.
fn open_integrity<D: Disk>(disk: D, dir: &Path) -> Result<(IntegrityJournal<D>, u64), LogError> {
    let mut journal = IntegrityJournal::open(disk, dir)?.journal;
    let epoch = current_epoch(&journal.records()?);
    Ok((journal, epoch))
}

/// Refuses a log recovered to `written` below what the current subject's
/// seals in `dir` cover, reading the journal only; returns that subject,
/// so the open reads the journal's records once (karyos#990 review).
fn check_seals<D: Disk + Clone>(disk: &D, dir: &Path, written: u64) -> Result<u64, LogError> {
    let (records, _) = read_records(&mut ReadOnly(disk.clone()), dir)?;
    let epoch = current_epoch(&records);
    match shortened_below_seal(&records, epoch, written) {
        Some(damage) => Err(LogError::ShortenedBelowSeal(damage)),
        None => Ok(epoch),
    }
}

/// What [`RaftLog::open`] found.
#[derive(Debug)]
pub struct Opened<D: Disk + Clone> {
    /// The log.
    pub log: RaftLog<D>,
    /// Where recovery cut the log, A2 or the frame walk, if it did. It
    /// covers the cuts recovery makes: writes whose index entries never
    /// reached the disk leave nothing to cut and are not reported, so the
    /// reopened [`RaftLog::last_index`] is what was kept, above the
    /// watermark either way.
    pub cut: Option<u64>,
}

fn encode_origin(origin: u64, snapshot_base: Option<u64>) -> [u8; ORIGIN_LEN] {
    let mut bytes = [0u8; ORIGIN_LEN];
    let (body, crc) = bytes.split_at_mut(16);
    let (first, base) = body.split_at_mut(8);
    first.copy_from_slice(&origin.to_le_bytes());
    base.copy_from_slice(&snapshot_base.unwrap_or(u64::MAX).to_le_bytes());
    let digest = crc32c(body);
    crc.copy_from_slice(&digest.to_le_bytes());
    bytes
}

/// The origin and the installed base, when the record is whole.
fn decode_origin(bytes: &[u8]) -> Option<(u64, Option<u64>)> {
    let record: &[u8; ORIGIN_LEN] = bytes.try_into().ok()?;
    let (body, crc) = record.split_first_chunk::<16>()?;
    let crc: [u8; 4] = crc.try_into().ok()?;
    let (origin, base) = body.split_first_chunk::<8>()?;
    let base: [u8; 8] = base.try_into().ok()?;
    let base = u64::from_le_bytes(base);
    (u32::from_le_bytes(crc) == crc32c(body)).then(|| {
        (
            u64::from_le_bytes(*origin),
            (base != u64::MAX).then_some(base),
        )
    })
}

fn encode_first(first: u64) -> [u8; FIRST_LEN] {
    let mut bytes = [0u8; FIRST_LEN];
    let (index, crc) = bytes.split_at_mut(8);
    index.copy_from_slice(&first.to_le_bytes());
    crc.copy_from_slice(&crc32c(&first.to_le_bytes()).to_le_bytes());
    bytes
}

fn encode_installed(first: u64, base_term: u64) -> [u8; INSTALLED_LEN] {
    let mut bytes = [0u8; INSTALLED_LEN];
    let (body, crc) = bytes.split_at_mut(16);
    let (index, term) = body.split_at_mut(8);
    index.copy_from_slice(&first.to_le_bytes());
    term.copy_from_slice(&base_term.to_le_bytes());
    let digest = crc32c(body);
    crc.copy_from_slice(&digest.to_le_bytes());
    bytes
}

/// The first index, and the base term when the record is an install's.
fn decode_first(bytes: &[u8]) -> Option<(u64, Option<u64>)> {
    if let Ok(record) = <&[u8; INSTALLED_LEN]>::try_from(bytes) {
        let (body, crc) = record.split_first_chunk::<16>()?;
        let crc: [u8; 4] = crc.try_into().ok()?;
        let (index, term) = body.split_first_chunk::<8>()?;
        let term: [u8; 8] = term.try_into().ok()?;
        return (u32::from_le_bytes(crc) == crc32c(body))
            .then(|| (u64::from_le_bytes(*index), Some(u64::from_le_bytes(term))));
    }
    let record: &[u8; FIRST_LEN] = bytes.try_into().ok()?;
    let (index, crc) = record.split_first_chunk::<8>()?;
    let crc: [u8; 4] = crc.try_into().ok()?;
    (u32::from_le_bytes(crc) == crc32c(index)).then(|| (u64::from_le_bytes(*index), None))
}

impl<D: Disk + Clone> RaftLog<D> {
    /// Creates an empty log in `dir`, whose first entry will be
    /// `first_index`. The first-index file is written atomically before
    /// the store, so a crash inside leaves a directory [`RaftLog::open`]
    /// finishes, or one this creates again.
    ///
    /// # Errors
    ///
    /// [`LogError::Exists`] when a log, or what is left of one, is in
    /// `dir` (its store, first-index or hard-state file, or a watermark
    /// other than the unset one a creation cut short leaves), changing
    /// nothing: a lost store is [`RaftLog::open`]'s to refuse, never to be
    /// created over. The disk's errors.
    pub fn create(
        mut disk: D,
        dir: &Path,
        geometry: Geometry,
        first_index: u64,
    ) -> Result<Self, LogError> {
        let names = disk.list(dir)?;
        let prefix = format!("{LOG_RECORDING:016x}-");
        if names.iter().any(|name| {
            name.starts_with(&prefix)
                || name == FIRST_INDEX_FILE
                || name == HARD_STATE_FILE
                || name == JOURNAL_FILE
        }) {
            return Err(LogError::Exists);
        }
        // A creation cut short leaves its mark unset, at sequence 1; any
        // other valid mark is a log's evidence, never reset.
        if names.iter().any(|name| name == MARK_FILE) {
            let left = match file::read(&mut disk, dir, MARK_FILE, MARK_LEN)? {
                Read::Bytes(bytes) => mark::newest(&bytes).map(|(_, slot)| slot),
                Read::Missing => None,
                Read::TooLong(_) => return Err(LogError::Exists),
            };
            if left.is_some_and(|slot| slot != CREATED.1) {
                return Err(LogError::Exists);
            }
        }
        let mark_file = mark::create(&mut disk, dir)?;
        // The origin before the first index: a log whose first-index file
        // exists knows where it began.
        file::replace(
            &mut disk,
            dir,
            ORIGIN_FILE,
            &encode_origin(first_index, None),
        )?;
        file::replace(&mut disk, dir, FIRST_INDEX_FILE, &encode_first(first_index))?;
        let mut log =
            Self::create_store(disk, dir, geometry, first_index, mark_file, CREATED, None)?;
        log.origin = Some(first_index);
        Ok(log)
    }

    fn create_store(
        disk: D,
        dir: &Path,
        geometry: Geometry,
        first_index: u64,
        mark_file: D::File,
        (mark_slot, mark): (usize, Slot),
        hard_state: Option<HardState>,
    ) -> Result<Self, LogError> {
        let store = SegmentStore::create(
            disk.clone(),
            dir,
            LOG_RECORDING,
            geometry,
            SyncPolicy::PerSegment,
            0,
        )?;
        let (integrity, epoch) = open_integrity(disk.clone(), dir)?;
        Ok(Self {
            store,
            disk,
            dir: dir.to_path_buf(),
            first_index,
            entries: Vec::new(),
            base_term: None,
            origin: None,
            snapshot_base: None,
            hard_state,
            poisoned: false,
            mark_file,
            mark_slot,
            mark,
            integrity,
            epoch,
            seal_buf: Vec::new(),
            seal_interval_ns: DEFAULT_SEAL_INTERVAL_NS,
            tail_since: None,
        })
    }

    /// Opens the log in `dir` after a crash or a close. It loads the hard
    /// state and the watermark, asks A2 for its recovery plan
    /// ([`SegmentStore::verify`], read-only) and walks the frames the plan
    /// keeps; only once every check passes does A2 apply its plan and the
    /// torn tail get cut, so a refused open writes nothing. A creation cut
    /// short (a plan that keeps no segment) is finished here as an empty
    /// log, with the stored term and vote.
    ///
    /// # Errors
    ///
    /// [`LogError::FirstIndex`]; [`LogError::Mark`] for a watermark with
    /// no valid slot; [`LogError::HardState`] for a refused record;
    /// [`LogError::Corruption`] when the log would end below the watermark
    /// or a segment is lost; [`LogError::Chain`] for a frame that does not
    /// continue the chain; [`LogError::TornBelowCommit`] and
    /// [`LogError::CommitBeyondDurable`] for a stored commit the kept log
    /// does not hold; the store's and the disk's errors.
    pub fn open(disk: D, dir: &Path, geometry: Geometry) -> Result<Opened<D>, LogError> {
        Self::open_with::<D>(disk, dir, geometry, None)
    }

    /// [`RaftLog::open`] for a log that may hold an install
    /// ([`RaftLog::install`]): `snapshots` is the node's snapshot store. A
    /// log whose first index an install set opens only when the store's
    /// latest snapshot verifies at that base; an install a crash cut short
    /// is then finished: the frames below the first index are dropped and
    /// the commit is the base.
    ///
    /// # Errors
    ///
    /// As [`RaftLog::open`], and [`LogError::InstallUnverified`] for an
    /// installed log without its snapshot.
    pub fn open_with<E: Disk + Clone>(
        disk: D,
        dir: &Path,
        geometry: Geometry,
        snapshots: Option<&SnapshotStore<E>>,
    ) -> Result<Opened<D>, LogError> {
        Self::open_with_under(disk, dir, geometry, snapshots, &HoldState::None)
    }

    /// [`RaftLog::open_with`] under the Archive's hold on the log: an open
    /// that would finish removing committed bytes a crash left half
    /// removed (segments below A2's published floor, an install's frames
    /// below its first index) refuses while `hold` holds, or may, and
    /// writes nothing; the bytes stay until the hold is released. An open
    /// with nothing to remove is not held back.
    ///
    /// # Errors
    ///
    /// As [`RaftLog::open_with`], and [`LogError::ArchiveHeld`].
    pub fn open_with_under<E: Disk + Clone>(
        mut disk: D,
        dir: &Path,
        geometry: Geometry,
        snapshots: Option<&SnapshotStore<E>>,
        hold: &impl HoldSource,
    ) -> Result<Opened<D>, LogError> {
        let (first_index, base_term) =
            match file::read(&mut disk, dir, FIRST_INDEX_FILE, INSTALLED_LEN)? {
                Read::Bytes(bytes) => decode_first(&bytes),
                Read::Missing | Read::TooLong(_) => None,
            }
            .ok_or(LogError::FirstIndex)?;
        // An installed log opens only over its verified snapshot.
        let base = match base_term {
            Some(term) => {
                let index = first_index
                    .checked_sub(1)
                    .ok_or(LogError::InstallUnverified { index: 0, term })?;
                verify_base(snapshots, (index, term), Base::OrLater)?;
                Some(index)
            }
            None => None,
        };
        // The origin file, when the log keeps one; an install cut short
        // before updating it still names its base in the first-index
        // record.
        let (origin, kept_base) = match file::read(&mut disk, dir, ORIGIN_FILE, ORIGIN_LEN)? {
            Read::Bytes(bytes) => decode_origin(&bytes).ok_or(LogError::FirstIndex)?,
            Read::Missing | Read::TooLong(_) => (u64::MAX, None),
        };
        let origin = ((origin != u64::MAX).then_some(origin), kept_base.max(base));
        let hard_state = match file::read(&mut disk, dir, HARD_STATE_FILE, HARD_STATE_LEN)? {
            Read::Missing => None,
            Read::Bytes(bytes) => Some(HardState::decode(&bytes).map_err(LogError::HardState)?),
            Read::TooLong(length) => {
                let length = usize::try_from(length).unwrap_or(usize::MAX);
                return Err(LogError::HardState(HardStateProblem::Length(length)));
            }
        };
        // Creation writes the mark durably before the first-index file: a
        // first-index file without a valid slot beside it is damage.
        let (mark_slot, mark) = match file::read(&mut disk, dir, MARK_FILE, MARK_LEN)? {
            Read::Bytes(bytes) => mark::newest(&bytes).ok_or(LogError::Mark)?,
            Read::Missing | Read::TooLong(_) => return Err(LogError::Mark),
        };
        let mark_file = disk.open(&dir.join(MARK_FILE))?;
        // An install cut short before its hard state keeps the stored
        // commit, below the base: the checks below allow up to the base,
        // and `finish_install` saves it once the open succeeds.
        // Plan first: nothing is cut before the log decides.
        let plan = match SegmentStore::verify(disk.clone(), dir, LOG_RECORDING, geometry) {
            Ok(plan) => plan,
            Err(SegmentError::BadHeader { base, .. }) => {
                return Err(LogError::Corruption(Corruption::Segment { base }));
            }
            Err(error) => return Err(LogError::Store(error)),
        };
        let Some(kept) = plan.kept else {
            // A creation that stopped before the store had a valid header:
            // recovery removes what it began, and the log starts empty,
            // with its stored term and vote.
            if base.is_none() {
                check_mark(mark.durable, None)?;
            }
            check_seals(&disk, dir, 0)?;
            if let Some(commit) = hard_state.and_then(|state| state.commit)
                && base.is_none_or(|base| commit > base)
            {
                return Err(LogError::CommitBeyondDurable {
                    commit,
                    durable: None,
                });
            }
            match SegmentStore::recover(
                disk.clone(),
                dir,
                LOG_RECORDING,
                geometry,
                SyncPolicy::PerSegment,
            ) {
                Ok(_) | Err(SegmentError::NotFound { .. }) => {}
                Err(error) => return Err(LogError::Store(error)),
            }
            let mut log = Self::create_store(
                disk,
                dir,
                geometry,
                first_index,
                mark_file,
                (mark_slot, mark),
                hard_state,
            )?;
            log.base_term = base_term;
            (log.origin, log.snapshot_base) = origin;
            log.finish_install()?;
            return Ok(Opened { log, cut: None });
        };
        // A store that starts past 0 was purged (C8b). A2's floor is
        // published before the first-index file follows it, so a crash
        // between them leaves the file below the first frame: the first
        // frame's index is the log's, rewritten once the open succeeds.
        let stored_first = first_index;
        // An install cut short after its record, before its frames were
        // dropped: the frames start below the first index, and all of
        // them go (the verified snapshot holds what they held).
        let stale = base.is_some() && kept.written > kept.start && {
            let mut reader = RawReader::new(&mut disk, dir, geometry);
            let mut header = [0u8; FRAME_HEADER];
            reader.read(kept.start, &mut header)?;
            Header::decode(&header).is_some_and(|frame| frame.index < first_index)
        };
        let first_index = if !stale && kept.start > 0 && kept.written > kept.start {
            let mut reader = RawReader::new(&mut disk, dir, geometry);
            let mut header = [0u8; FRAME_HEADER];
            reader.read(kept.start, &mut header)?;
            Header::decode(&header)
                .map(|frame| frame.index)
                .filter(|index| *index > first_index)
                .unwrap_or(first_index)
        } else {
            first_index
        };
        let walk = if stale {
            Walk {
                entries: Vec::new(),
                torn: None,
            }
        } else {
            let mut reader = RawReader::new(&mut disk, dir, geometry);
            walk(
                &mut reader,
                (kept.start, kept.written),
                (first_index, base_term),
                geometry,
            )?
        };
        let last = index_after(first_index, walk.entries.len());
        // Where the log will end, checked against its seals before any
        // other check: a sealed range lost is named as such (karyos#990).
        let end = if stale {
            kept.start
        } else {
            walk.torn.map_or(kept.written, |(position, _)| position)
        };
        let epoch = check_seals(&disk, dir, end)?;
        if let (Some((_, index)), Some(commit)) =
            (walk.torn, hard_state.and_then(|state| state.commit))
            && index <= commit
        {
            return Err(LogError::TornBelowCommit { index, commit });
        }
        if !stale {
            check_mark(mark.durable, last)?;
        }
        if let Some(commit) = hard_state.and_then(|state| state.commit)
            && last.is_none_or(|last| commit > last)
            && base.is_none_or(|base| commit > base)
        {
            return Err(LogError::CommitBeyondDurable {
                commit,
                durable: last,
            });
        }
        // A purge's segments below A2's floor, or an install's frames
        // below its first index, are committed bytes a crash left half
        // removed: not removed through an Archive hold.
        let purging = plan
            .dropped
            .iter()
            .any(|dropped| dropped.reason == DropReason::Purged);
        if purging || stale {
            Self::check_not_held(hold)?;
        }
        // Decided: apply A2's plan, then cut the torn tail.
        let recovered = SegmentStore::recover(
            disk.clone(),
            dir,
            LOG_RECORDING,
            geometry,
            SyncPolicy::PerSegment,
        )?;
        let mut store = recovered.store;
        if store.written() != kept.written {
            return Err(LogError::Store(SegmentError::NotContiguous {
                expected: kept.written,
                got: store.written(),
            }));
        }
        if let Some((position, _)) = walk.torn {
            store.truncate(position)?;
        }
        if stale {
            store.truncate(kept.start)?;
        }
        // The subject check_seals read: the journal's records are read once.
        let integrity = IntegrityJournal::open(disk.clone(), dir)?.journal;
        let mut log = Self {
            store,
            disk,
            dir: dir.to_path_buf(),
            first_index,
            entries: walk.entries,
            base_term,
            origin: None,
            snapshot_base: None,
            hard_state,
            poisoned: false,
            mark_file,
            mark_slot,
            mark,
            integrity,
            epoch,
            seal_buf: Vec::new(),
            seal_interval_ns: DEFAULT_SEAL_INTERVAL_NS,
            tail_since: None,
        };
        if first_index != stored_first {
            file::replace(
                &mut log.disk,
                dir,
                FIRST_INDEX_FILE,
                &encode_first(first_index),
            )?;
        }
        // What recovery kept is durable: the mark follows it.
        log.write_mark(log.last_index())?;
        (log.origin, log.snapshot_base) = origin;
        log.finish_install()?;
        Ok(Opened {
            log,
            cut: walk
                .torn
                .map(|(position, _)| position)
                .or(plan.cut.map(|cut| cut.position)),
        })
    }

    /// The first index.
    #[must_use]
    pub fn first_index(&self) -> u64 {
        self.first_index
    }

    /// The last index written, or `None` while the log is empty.
    #[must_use]
    pub fn last_index(&self) -> Option<u64> {
        self.index_of(self.entries.len())
    }

    /// The index the next append starts at; `None` once the last index
    /// is `u64::MAX`.
    #[must_use]
    pub fn next_index(&self) -> Option<u64> {
        self.last_index()
            .map_or(Some(self.first_index), |last| last.checked_add(1))
    }

    /// The index of the last of the first `count` entries; `None` for 0.
    fn index_of(&self, count: usize) -> Option<u64> {
        let count = u64::try_from(count).ok()?.checked_sub(1)?;
        self.first_index.checked_add(count)
    }

    /// The last index whose whole frame is durable, or `None`.
    #[must_use]
    pub fn durable_index(&self) -> Option<u64> {
        // Never past the watermark: a segment roll's sync makes A2's
        // durable run ahead of what a sync reported.
        let stored = self.stored_durable_index();
        match (stored, self.mark.durable) {
            (Some(stored), Some(mark)) => Some(stored.min(mark)),
            _ => None,
        }
    }

    /// The last index A2 holds durable.
    fn stored_durable_index(&self) -> Option<u64> {
        let durable = self.store.durable();
        let count = if self.store.written() <= durable {
            self.entries.len()
        } else {
            // Entry `k` ends where `k + 1` starts: those before the first
            // entry starting past `durable`, but the last of them.
            let starting = self.entries.partition_point(|(start, _)| *start <= durable);
            if starting == 0 { 0 } else { starting - 1 }
        };
        self.index_of(count)
    }

    /// A2's written position: the end of the last frame.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.store.written()
    }

    /// A2's durable position.
    #[must_use]
    pub fn durable(&self) -> u64 {
        self.store.durable()
    }

    /// The term of entry `index`, if the log holds it.
    #[must_use]
    pub fn term(&self, index: u64) -> Option<u64> {
        self.slot(index)
            .and_then(|slot| self.entries.get(slot))
            .map(|(_, term)| *term)
            .or_else(|| {
                self.base_term
                    .filter(|_| self.first_index.checked_sub(1) == Some(index))
            })
    }

    /// The base an install set: the index before the first one and its
    /// term, while the log's first index is the install's.
    #[must_use]
    pub fn base(&self) -> Option<(u64, u64)> {
        let term = self.base_term?;
        Some((self.first_index.checked_sub(1)?, term))
    }

    /// Discards every entry and restarts the log after a snapshot at
    /// `base_index` of `base_term`, which `snapshots` already holds
    /// durably as its latest: a follower installing a leader's snapshot
    /// (W5; decided 2026-10-30 by QS-COORDINATOR). When the log already
    /// holds `base_index` at `base_term`, Raft keeps the entries after it
    /// (figure 13, step 6): the caller does not install then. A vote of an
    /// older term than the base's is dropped. Durable on return, in this
    /// order:
    ///
    /// 1. the first-index file names `base_index + 1` and `base_term`, in
    ///    one record, replaced atomically;
    /// 2. the watermark is cleared;
    /// 3. A2 cuts every frame;
    /// 4. the hard state's commit becomes `base_index`.
    ///
    /// A crash after 1 leaves a log [`RaftLog::open_with`] finishes over
    /// the same verified snapshot, and refuses without it; a crash before
    /// it leaves the log as it was.
    ///
    /// # Errors
    ///
    /// [`LogError::ArchiveHeld`] while the Archive holds the log, or may
    /// ([`RaftLog::install_under`]; [`RaftLog::install`] holds nothing): an
    /// install cuts every entry;
    /// [`LogError::InstallUnverified`] unless the store's latest snapshot
    /// verifies at that base, and [`LogError::InstallStale`] for a base
    /// not past the stored commit, all changing nothing;
    /// [`LogError::Poisoned`]; the store's and the disk's errors, which
    /// poison.
    pub fn install<E: Disk + Clone>(
        &mut self,
        base_index: u64,
        base_term: u64,
        snapshots: &SnapshotStore<E>,
    ) -> Result<(), LogError> {
        self.install_under(base_index, base_term, snapshots, &HoldState::None)
    }

    /// [`RaftLog::install`] under the Archive's hold on the log, read from
    /// `hold` right before anything is written.
    ///
    /// # Errors
    ///
    /// As [`RaftLog::install`].
    pub fn install_under<E: Disk + Clone>(
        &mut self,
        base_index: u64,
        base_term: u64,
        snapshots: &SnapshotStore<E>,
        hold: &impl HoldSource,
    ) -> Result<(), LogError> {
        self.check_writable()?;
        Self::check_not_held(hold)?;
        verify_base(Some(snapshots), (base_index, base_term), Base::Exact)?;
        let commit = self.hard_state.and_then(|state| state.commit);
        if commit.is_some_and(|commit| base_index <= commit) {
            return Err(LogError::InstallStale {
                index: base_index,
                commit,
            });
        }
        let first = base_index
            .checked_add(1)
            .ok_or(LogError::TooLarge { index: base_index })?;
        // The cut removes sealed bytes: the log's bytes from it on are
        // sealed under the next subject, started before anything is cut.
        let cut = self
            .entries
            .first()
            .map_or(self.store.written(), |&(start, _)| start);
        self.begin_epoch(cut)?;
        if let Err(error) = file::replace(
            &mut self.disk,
            &self.dir,
            FIRST_INDEX_FILE,
            &encode_installed(first, base_term),
        ) {
            self.poisoned = true;
            return Err(LogError::Io(error));
        }
        // The installed base outlives later purges of the first-index
        // record: kept in the origin file.
        if let Err(error) = file::replace(
            &mut self.disk,
            &self.dir,
            ORIGIN_FILE,
            &encode_origin(self.origin.unwrap_or(u64::MAX), Some(base_index)),
        ) {
            self.poisoned = true;
            return Err(LogError::Io(error));
        }
        self.snapshot_base = Some(base_index);
        self.write_mark(None)?;
        if let Some(&(start, _)) = self.entries.first() {
            let cut = self.store.truncate(start);
            self.poison_on(cut)?;
        }
        self.entries.clear();
        self.first_index = first;
        self.base_term = Some(base_term);
        self.finish_install()
    }

    /// An install's last step: the hard state's commit is at least the
    /// base, and its term not below the base's.
    fn finish_install(&mut self) -> Result<(), LogError> {
        let Some((base, term)) = self.base() else {
            return Ok(());
        };
        let stored = self.hard_state;
        if stored
            .and_then(|state| state.commit)
            .is_some_and(|commit| commit >= base)
        {
            return Ok(());
        }
        // A vote is for its own term: one of an older term than the base's
        // does not carry into it (karyos#903 review, codex).
        let state = match stored {
            Some(state) if state.current_term >= term => HardState {
                commit: Some(base),
                ..state
            },
            _ => HardState {
                current_term: term,
                voted_for: None,
                commit: Some(base),
            },
        };
        match file::replace(&mut self.disk, &self.dir, HARD_STATE_FILE, &state.encode()) {
            Ok(()) => {
                self.hard_state = Some(state);
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(LogError::Io(error))
            }
        }
    }

    /// The bytes entry `index`'s frame spans in the log, from its start to
    /// the next frame's (any padding between included), read from the
    /// in-memory index without touching the store; `None` when the log
    /// does not hold it.
    #[must_use]
    pub fn frame_span(&self, index: u64) -> Option<u64> {
        let slot = self.slot(index)?;
        let (start, _) = *self.entries.get(slot)?;
        let end = match slot.checked_add(1).and_then(|next| self.entries.get(next)) {
            Some((next, _)) => *next,
            None => self.store.written(),
        };
        end.checked_sub(start)
    }

    fn slot(&self, index: u64) -> Option<usize> {
        usize::try_from(index.checked_sub(self.first_index)?).ok()
    }

    fn check_writable(&self) -> Result<(), LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        Ok(())
    }

    /// Refuses an operation that removes committed bytes while the Archive
    /// holds the log, or may: fail closed.
    fn check_not_held(hold: &impl HoldSource) -> Result<(), LogError> {
        match hold.hold_state() {
            HoldState::None => Ok(()),
            state => Err(LogError::ArchiveHeld { state }),
        }
    }

    /// Poisons the log on an error of the store, keeping in the index only
    /// the frames A2 still holds whole.
    fn poison_on<T>(&mut self, result: Result<T, SegmentError>) -> Result<T, LogError> {
        if result.is_err() {
            self.poisoned = true;
            let written = self.store.written();
            let ends: Vec<u64> = self
                .entries
                .iter()
                .skip(1)
                .map(|(start, _)| *start)
                .chain(std::iter::once(written))
                .collect();
            let kept = ends.iter().take_while(|end| **end <= written).count();
            self.entries.truncate(kept);
        }
        result.map_err(LogError::Store)
    }

    /// Appends `entries`, each starting at [`RaftLog::next_index`] and not
    /// lowering the term; returns the last index written. Not durable
    /// until [`RaftLog::sync`].
    ///
    /// # Errors
    ///
    /// [`LogError::NotNext`], [`LogError::TermBack`] and
    /// [`LogError::TooLarge`], checked for every entry before anything is
    /// written; [`LogError::Poisoned`]; the store's errors (a segment
    /// roll's sync included), which poison the log.
    pub fn append(&mut self, entries: &[Entry]) -> Result<Option<u64>, LogError> {
        self.check_writable()?;
        let mut expected = self
            .next_index()
            .ok_or(LogError::TooLarge { index: u64::MAX })?;
        // An installed log that holds nothing yet goes on from its base's
        // term: terms never go back across the base (karyos#903 review).
        let mut last = self
            .entries
            .last()
            .map(|(_, term)| *term)
            .or(self.base_term);
        let mut frames = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.index != expected {
                return Err(LogError::NotNext {
                    expected,
                    got: entry.index,
                });
            }
            if let Some(last) = last.filter(|last| entry.term < *last) {
                return Err(LogError::TermBack {
                    index: entry.index,
                    last,
                    got: entry.term,
                });
            }
            frames.push((entry.term, entry.frame()?));
            last = Some(entry.term);
            expected = expected
                .checked_add(1)
                .ok_or(LogError::TooLarge { index: entry.index })?;
        }
        for (term, frame) in frames {
            let position = self.store.written();
            let appended = self.store.append(position, &frame);
            self.poison_on(appended)?;
            self.entries.push((position, term));
        }
        Ok(self.last_index())
    }

    /// Makes every written entry durable, then records it in the durable
    /// watermark ([`crate::mark`]); returns the durable last index. A
    /// follower acknowledges entries as persisted (the caller's
    /// persistence callback) only after this returns: recovery refuses to
    /// lose anything the watermark covers.
    ///
    /// # Errors
    ///
    /// [`LogError::Poisoned`]; the store's errors, and the watermark's
    /// [`LogError::Io`], each of which poisons the log.
    pub fn sync(&mut self) -> Result<Option<u64>, LogError> {
        self.check_writable()?;
        let synced = self.store.sync();
        self.poison_on(synced)?;
        self.write_mark(self.stored_durable_index())?;
        Ok(self.durable_index())
    }

    /// The watermark, the last index a sync reported durable.
    #[must_use]
    pub fn mark(&self) -> Option<u64> {
        self.mark.durable
    }

    /// Records `durable` as the mark: in the older slot, with the next
    /// sequence, then synced. Nothing to do when it is the mark already. A
    /// failure poisons the log.
    fn write_mark(&mut self, durable: Option<u64>) -> Result<(), LogError> {
        if durable == self.mark.durable {
            return Ok(());
        }
        let Some(sequence) = self.mark.sequence.checked_add(1) else {
            self.poisoned = true;
            return Err(LogError::Poisoned);
        };
        let slot = Slot { sequence, durable };
        let at = 1 - self.mark_slot.min(1);
        match mark::write(&mut self.disk, &self.mark_file, at, slot) {
            Ok(()) => {
                self.mark = slot;
                self.mark_slot = at;
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(LogError::Io(error))
            }
        }
    }

    /// Removes entry `from_index` and every later one; appends restart at
    /// `from_index`. What is kept is durable on return.
    ///
    /// # Errors
    ///
    /// [`LogError::OutOfRange`] outside `[first_index, last_index + 1]`
    /// and [`LogError::TruncateBelowCommit`] at or below the stored
    /// commit, which change nothing; [`LogError::Poisoned`]; the store's
    /// errors, which poison the log.
    pub fn truncate_suffix(&mut self, from_index: u64) -> Result<(), LogError> {
        self.check_writable()?;
        if let Some(commit) = self
            .hard_state
            .and_then(|state| state.commit)
            .filter(|commit| from_index <= *commit)
        {
            return Err(LogError::TruncateBelowCommit {
                from: from_index,
                commit,
            });
        }
        let out = || LogError::OutOfRange {
            index: from_index,
            first: self.first_index,
            last: self.last_index(),
        };
        let slot = self.slot(from_index).ok_or_else(out)?;
        let position = match self.entries.get(slot) {
            Some((position, _)) => *position,
            None if slot == self.entries.len() => return Ok(()),
            None => return Err(out()),
        };
        // The mark comes down first: a crash after A2's cut then finds it at
        // or below the cut.
        let kept = from_index
            .checked_sub(1)
            .filter(|_| from_index > self.first_index);
        if self
            .mark
            .durable
            .is_some_and(|mark| kept.is_none_or(|kept| mark > kept))
        {
            self.write_mark(kept)?;
        }
        let truncated = self.store.truncate(position);
        self.poison_on(truncated)?;
        self.entries.truncate(slot);
        // What is kept is durable now: the mark follows it up.
        self.write_mark(self.stored_durable_index())
    }

    /// Purges the entries below `below` and returns the new first index:
    /// `below`, or the last index when `below` is past it (the log keeps
    /// at least its last entry, so its next index stays known), or the
    /// first index when `below` is not past it (C8b). A2 moves the
    /// recording's start to the first kept frame and removes the whole
    /// segments below it; the bytes of purged entries in the first kept
    /// segment stay in its file, unread. Durable on return.
    ///
    /// A2 publishes the purge by its floor record before it removes a
    /// segment, then the first-index file follows; a crash between them
    /// leaves a first-index file below the first frame, and
    /// [`RaftLog::open`] takes the first frame's index and rewrites it.
    ///
    /// # Errors
    ///
    /// [`LogError::ArchiveHeld`] while the Archive holds the log, or may
    /// ([`RaftLog::purge_prefix_under`]; [`RaftLog::purge_prefix`] holds
    /// nothing), and [`LogError::PurgeBeyondCommit`]
    /// for `below` past the stored commit plus one, both changing nothing; [`LogError::Poisoned`]; the store's
    /// and the disk's errors, which poison the log.
    pub fn purge_prefix(&mut self, below: u64) -> Result<u64, LogError> {
        self.purge_prefix_under(below, &HoldState::None)
    }

    /// [`RaftLog::purge_prefix`] under the Archive's hold on the log, read
    /// from `hold` right before anything is written.
    ///
    /// # Errors
    ///
    /// As [`RaftLog::purge_prefix`].
    pub fn purge_prefix_under(
        &mut self,
        below: u64,
        hold: &impl HoldSource,
    ) -> Result<u64, LogError> {
        self.check_writable()?;
        Self::check_not_held(hold)?;
        let commit = self.hard_state.and_then(|state| state.commit);
        if commit
            .and_then(|commit| commit.checked_add(1))
            .is_none_or(|limit| below > limit)
        {
            return Err(LogError::PurgeBeyondCommit { below, commit });
        }
        let Some(last_slot) = self.entries.len().checked_sub(1) else {
            return Ok(self.first_index);
        };
        let kept = self.slot(below).unwrap_or(0).min(last_slot);
        if kept == 0 {
            return Ok(self.first_index);
        }
        let Some((position, _)) = self.entries.get(kept).copied() else {
            return Ok(self.first_index);
        };
        let first = u64::try_from(kept)
            .ok()
            .and_then(|kept| self.first_index.checked_add(kept))
            .ok_or(LogError::TooLarge { index: below })?;
        // The committed tail a commit advance left unsealed is sealed
        // before any of it is removed (karyos#1050).
        if let Err(error) = self.seal_committed(true) {
            self.poisoned = true;
            return Err(error);
        }
        let purged = self.store.purge_before(position);
        let _ = self.poison_on(purged)?;
        if let Err(error) = file::replace(
            &mut self.disk,
            &self.dir,
            FIRST_INDEX_FILE,
            &encode_first(first),
        ) {
            self.poisoned = true;
            return Err(LogError::Io(error));
        }
        let _ = self.entries.drain(..kept);
        self.first_index = first;
        // The plain record replaced the install's: its base is purged.
        self.base_term = None;
        Ok(first)
    }

    /// The entries of `range` the log holds, in order, stopping before the
    /// one that would take their encoded size ([`Entry::encoded_len`]) past
    /// `max_bytes`; the first is returned whatever its size, so a range is
    /// never refused.
    ///
    /// Every frame is checked against the in-memory index before its
    /// payload is read or allocated, then by its CRC-32C (karyos#904): its
    /// header must name the indexed index and term, and its header and
    /// payload must span exactly the bytes from its position to the next
    /// frame's, or for the last fit before the written end. A frame that does not is a typed
    /// [`LogError::Chain`], never a short, long or wrong entry. A read
    /// changes nothing, so it does not poison the log: the bytes on disk
    /// stay as they are, and the next open walks them again.
    ///
    /// # Errors
    ///
    /// The store's errors, and [`LogError::Chain`] for a frame that no
    /// longer reads as the one the index holds.
    pub fn entries(&mut self, range: Range<u64>, max_bytes: u64) -> Result<Vec<Entry>, LogError> {
        let mut found = Vec::new();
        let mut window = Vec::new();
        self.entries_into(range, max_bytes, &mut found, &mut window)?;
        Ok(found)
    }

    /// [`Self::entries`] into `out`, with `window` as the read buffer: the
    /// same entries, checks and errors, but `out`'s entries and their
    /// payload buffers are reused in place, and `window` keeps its
    /// capacity, so a read that fits what an earlier one left allocates
    /// nothing (karyos#681). `out` ends holding exactly the entries read,
    /// and nothing on an error, even one past valid frames.
    ///
    /// # Errors
    ///
    /// As [`Self::entries`].
    pub fn entries_into(
        &mut self,
        range: Range<u64>,
        max_bytes: u64,
        out: &mut Vec<Entry>,
        window: &mut Vec<u8>,
    ) -> Result<(), LogError> {
        let mut filled = 0usize;
        let read = self.fill_entries(range, max_bytes, out, window, &mut filled);
        if read.is_err() {
            filled = 0;
        }
        out.truncate(filled);
        read
    }

    fn fill_entries(
        &mut self,
        range: Range<u64>,
        max_bytes: u64,
        out: &mut Vec<Entry>,
        window: &mut Vec<u8>,
        filled: &mut usize,
    ) -> Result<(), LogError> {
        let mut bytes = 0u64;
        let mut index = range.start;
        while index < range.end {
            // The frames the index places back to back from `index`, within
            // the budget and one read window: their spans are exact (each
            // ends at the next frame's position), so they are read at once
            // (karyos#1001). The log's last frame, whose span runs to the
            // written end, is read alone below.
            let Some(first) = self.slot(index) else {
                break;
            };
            let Some(&(start, _)) = self.entries.get(first) else {
                break;
            };
            let mut slot = first;
            let mut end = start;
            let mut planned = bytes;
            while let Some(&(next, _)) = slot.checked_add(1).and_then(|next| self.entries.get(next))
            {
                let at = index.saturating_add(u64::try_from(slot - first).unwrap_or(u64::MAX));
                if at >= range.end {
                    break;
                }
                let span = next.saturating_sub(end);
                let total = planned.saturating_add(span);
                let fits = (*filled == 0 && slot == first) || total <= max_bytes;
                if !fits || next.saturating_sub(start) > READ_WINDOW {
                    break;
                }
                planned = total;
                end = next;
                slot += 1;
            }
            if slot == first {
                // One frame alone: the log's last, one past the budget (its
                // header checked before the read stops), or one larger than
                // a window (read once, never copied again).
                let Some(claimed) =
                    self.entry_alone(index, first, bytes, max_bytes, out, *filled)?
                else {
                    break;
                };
                bytes = bytes.saturating_add(claimed);
                *filled += 1;
                index = index.saturating_add(1);
                continue;
            }
            let length = usize::try_from(end - start)
                .map_err(|_| LogError::Store(SegmentError::PositionOverflow))?;
            window.clear();
            window.resize(length, 0);
            self.store.read(start, window)?;
            for at in first..slot {
                let Some(&(position, term)) = self.entries.get(at) else {
                    break;
                };
                let span_end = self.entries.get(at + 1).map_or(end, |(next, _)| *next);
                let from = usize::try_from(position - start)
                    .map_err(|_| LogError::Store(SegmentError::PositionOverflow))?;
                let to = usize::try_from(span_end - start)
                    .map_err(|_| LogError::Store(SegmentError::PositionOverflow))?;
                let frame = window.get(from..to).unwrap_or(&[]);
                check_frame_into(frame, index, term, position, false, pooled(out, *filled)?)?;
                *filled += 1;
                index = index.saturating_add(1);
            }
            // Past the budget, the next frame's header is still read and
            // checked, alone, before the read stops.
            bytes = planned;
        }
        Ok(())
    }

    /// The entry at `slot`, read alone: the log's last frame (its span
    /// runs to the written end) or one larger than a read window, with its
    /// encoded size, read into slot `at` of `out`. `None` when it would
    /// take `bytes` past `max_bytes` and is not the first (`at` > 0): its
    /// header is checked, but no slot is taken, so a budget that stops at
    /// `out`'s capacity allocates nothing.
    fn entry_alone(
        &mut self,
        index: u64,
        slot: usize,
        bytes: u64,
        max_bytes: u64,
        out: &mut Vec<Entry>,
        at: usize,
    ) -> Result<Option<u64>, LogError> {
        let Some(&(position, term)) = self.entries.get(slot) else {
            return Ok(None);
        };
        let chain = |problem| LogError::Chain { position, problem };
        let (end, last) = match slot.checked_add(1).and_then(|next| self.entries.get(next)) {
            Some((next, _)) => (*next, false),
            None => (self.store.written(), true),
        };
        let span = end
            .checked_sub(position)
            .ok_or_else(|| chain(ChainProblem::PastEnd))?;
        let mut header = [0u8; FRAME_HEADER];
        self.store.read(position, &mut header)?;
        let frame = check_header(&header, index, term, position, span, last)?;
        let claimed = u64::from(frame.length).saturating_add(FRAME_HEADER_LEN);
        if at != 0
            && bytes
                .checked_add(claimed)
                .is_none_or(|total| total > max_bytes)
        {
            return Ok(None);
        }
        let entry = pooled(out, at)?;
        // Within the span the index gives: the allocation is bounded.
        let length = usize::try_from(frame.length).map_err(|_| chain(ChainProblem::PastEnd))?;
        entry.payload.clear();
        entry.payload.resize(length, 0);
        let at = position
            .checked_add(FRAME_HEADER_LEN)
            .ok_or(LogError::Store(SegmentError::PositionOverflow))?;
        self.store.read(at, &mut entry.payload)?;
        check_crc(&header, &entry.payload, frame.crc, position)?;
        entry.index = frame.index;
        entry.term = frame.term;
        entry.event_time = frame.event_time;
        Ok(Some(claimed))
    }

    /// The stored hard state, if any was saved.
    #[must_use]
    pub fn hard_state(&self) -> Option<HardState> {
        self.hard_state
    }

    fn check_commit(&self, commit: u64) -> Result<(), LogError> {
        let durable = self.durable_index();
        // The base an install set is durable in its snapshot.
        if self.base().is_some_and(|(base, _)| commit <= base) {
            return Ok(());
        }
        if durable.is_none_or(|durable| commit > durable) {
            return Err(LogError::CommitBeyondDurable { commit, durable });
        }
        Ok(())
    }

    /// Saves `state` durably: returns only after its sync. The stored
    /// commit only moves forward. [`HardState`] is one record, so a
    /// vote-only save (openraft's `save_vote`) must carry the stored
    /// commit ([`RaftLog::hard_state`]): a save with no commit after one
    /// was stored is refused. A failure poisons the log, which refuses
    /// every write until reopened.
    ///
    /// # Errors
    ///
    /// [`LogError::CommitBack`] and [`LogError::CommitBeyondDurable`],
    /// which change nothing; [`LogError::Poisoned`]; the disk's errors,
    /// which poison.
    pub fn save_hard_state(&mut self, state: HardState) -> Result<(), LogError> {
        self.check_writable()?;
        if let Some(stored) = self.hard_state.and_then(|stored| stored.commit)
            && state.commit.is_none_or(|commit| commit < stored)
        {
            return Err(LogError::CommitBack {
                stored,
                got: state.commit,
            });
        }
        if let Some(commit) = state.commit {
            self.check_commit(commit)?;
        }
        match file::replace(&mut self.disk, &self.dir, HARD_STATE_FILE, &state.encode()) {
            Ok(()) => {
                self.hard_state = Some(state);
            }
            Err(error) => {
                self.poisoned = true;
                return Err(LogError::Io(error));
            }
        }
        let sealed = self.seal_committed(false);
        if sealed.is_err() {
            self.poisoned = true;
        }
        sealed
    }

    /// Seals the committed log's tail, however short, as a clean close
    /// does (karyos#1050): a commit advance seals only whole
    /// [`SEAL_CHUNK`]s.
    ///
    /// # Errors
    ///
    /// [`LogError::Poisoned`]; the store's and the journal's errors, which
    /// poison the log.
    pub fn seal(&mut self) -> Result<(), LogError> {
        self.check_writable()?;
        let sealed = self.seal_committed(true);
        if sealed.is_err() {
            self.poisoned = true;
        }
        sealed
    }

    /// Seals the log's bytes up to the end of the stored commit's entry,
    /// from where the current subject's seals end (karyos#990): never a
    /// byte Raft may still truncate. Committed bytes are durable, so they
    /// read back as written. Unless `all`, only whole [`SEAL_CHUNK`]s are
    /// sealed, and a shorter tail waits (karyos#1050).
    fn seal_committed(&mut self, all: bool) -> Result<(), LogError> {
        let Some((commit, end)) = self.committed_end() else {
            return Ok(());
        };
        let mut start = match self.integrity.sealed_end(self.epoch) {
            Some(start) => start,
            None => self.store.start(),
        };
        // Bytes a purge removed before they were sealed cannot be sealed:
        // the seals go on under the next subject, from the store's start.
        if start < self.store.start() {
            self.begin_epoch(self.store.start())?;
            start = self.store.start();
        }
        while start < end {
            let chunk_end = end.min(start.saturating_add(SEAL_CHUNK));
            if !all && chunk_end.saturating_sub(start) < SEAL_CHUNK {
                break;
            }
            let length = usize::try_from(chunk_end.saturating_sub(start))
                .map_err(|_| LogError::TooLarge { index: commit })?;
            self.seal_buf.resize(length, 0);
            self.store.read(start, &mut self.seal_buf)?;
            self.integrity
                .seal_cluster_log(self.epoch, start, &self.seal_buf, chunk_end)?;
            start = chunk_end;
        }
        Ok(())
    }

    /// The stored commit and where its entry ends in the log, if the log
    /// holds it.
    fn committed_end(&self) -> Option<(u64, u64)> {
        let commit = self.hard_state.and_then(|state| state.commit)?;
        let slot = self
            .slot(commit)
            .filter(|&slot| slot < self.entries.len())?;
        let end = match slot.checked_add(1).and_then(|next| self.entries.get(next)) {
            Some(&(next, _)) => next,
            None => self.store.written(),
        };
        Some((commit, end))
    }

    /// Whether committed bytes wait unsealed.
    fn unsealed_tail(&self) -> bool {
        self.committed_end().is_some_and(|(_, end)| {
            self.integrity
                .sealed_end(self.epoch)
                .unwrap_or(self.store.start())
                < end
        })
    }

    /// Bounds how long a committed tail waits unsealed: `interval_ns` of
    /// the clock [`RaftLog::tick`] is given ([`DEFAULT_SEAL_INTERVAL_NS`]
    /// by default).
    pub fn set_seal_interval(&mut self, interval_ns: u64) {
        self.seal_interval_ns = interval_ns;
    }

    /// The host's periodic duty, at `now_ns` of its monotonic clock
    /// (karyos#1050 review): a committed tail shorter than [`SEAL_CHUNK`]
    /// that has waited unsealed for the seal interval is sealed, so a
    /// cluster committing slowly still has its log sealed within about
    /// one interval. Nothing is written otherwise.
    ///
    /// # Errors
    ///
    /// As [`RaftLog::seal`].
    pub fn tick(&mut self, now_ns: u64) -> Result<(), LogError> {
        if self.poisoned || !self.unsealed_tail() {
            self.tail_since = None;
            return Ok(());
        }
        match self.tail_since {
            None => {
                self.tail_since = Some(now_ns);
                Ok(())
            }
            Some(since) if now_ns.saturating_sub(since) >= self.seal_interval_ns => {
                self.tail_since = None;
                self.seal()
            }
            Some(_) => Ok(()),
        }
    }

    /// A clean shutdown (karyos#1050 review): seals the committed tail and
    /// syncs the log, so a reopened log's seals cover everything it
    /// committed.
    ///
    /// # Errors
    ///
    /// As [`RaftLog::seal`] and [`RaftLog::sync`].
    pub fn close(mut self) -> Result<(), LogError> {
        let _ = self.sync()?;
        self.seal()
    }

    /// Starts the next seal subject at `at`, with an empty range there, so
    /// a reopened log checks its end against the new subject's seals.
    fn begin_epoch(&mut self, at: u64) -> Result<(), LogError> {
        let next = self
            .epoch
            .checked_add(1)
            .ok_or(LogError::TooLarge { index: self.epoch })?;
        if let Err(error) = self
            .integrity
            .append(SealKind::ClusterLog, next, at, at, digest(&[]))
        {
            self.poisoned = true;
            return Err(error.into());
        }
        self.epoch = next;
        Ok(())
    }
}

/// Whether [`verify_base`] takes only a snapshot at exactly the base, or
/// also a later one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Base {
    /// An install: the latest snapshot is the base, index and term.
    Exact,
    /// An open: the latest snapshot is the base or a later one, which holds
    /// the base's state too (a compaction after the install; karyos#903
    /// review, codex).
    OrLater,
}

/// Refuses unless `snapshots`' latest snapshot verifies whole and is at
/// `index` of `term`, or under [`Base::OrLater`] past `index`.
fn verify_base<E: Disk + Clone>(
    snapshots: Option<&SnapshotStore<E>>,
    (index, term): (u64, u64),
    base: Base,
) -> Result<(), LogError> {
    let unverified = LogError::InstallUnverified { index, term };
    let store = snapshots.ok_or(unverified)?;
    let latest = store
        .latest()
        .filter(|info| {
            (info.index == index && info.term == term)
                || (base == Base::OrLater && info.index > index)
        })
        .ok_or(LogError::InstallUnverified { index, term })?;
    store
        .verify(&latest)
        .map_err(|_| LogError::InstallUnverified { index, term })
}

/// Refuses a log that would end at `last`, below the watermark `mark`.
fn check_mark(mark: Option<u64>, last: Option<u64>) -> Result<(), LogError> {
    match mark {
        Some(mark) if last.is_none_or(|last| last < mark) => {
            Err(LogError::Corruption(Corruption::BelowMark { last, mark }))
        }
        _ => Ok(()),
    }
}

/// The last index of a log from `first` holding `count` entries.
fn index_after(first: u64, count: usize) -> Option<u64> {
    let count = u64::try_from(count).ok()?.checked_sub(1)?;
    first.checked_add(count)
}

/// Reads the log's bytes from A2's data files, read-only, before recovery
/// (A2 names a segment's data `<recording>-<base>.seg`, both 16 hex
/// digits, and keeps position `p` at offset `p - base` of it). It repeats
/// A2's layout; a follow-up is a read-only reader exposed by A2 over a
/// plan.
struct RawReader<'a, D: Disk> {
    disk: &'a mut D,
    dir: &'a Path,
    geometry: Geometry,
    open: Option<(u64, D::File)>,
}

impl<'a, D: Disk> RawReader<'a, D> {
    fn new(disk: &'a mut D, dir: &'a Path, geometry: Geometry) -> Self {
        Self {
            disk,
            dir,
            geometry,
            open: None,
        }
    }

    fn read(&mut self, mut position: u64, mut buf: &mut [u8]) -> Result<(), LogError> {
        let segment = self.geometry.segment_length();
        let overflow = || LogError::Store(SegmentError::PositionOverflow);
        while !buf.is_empty() {
            let offset = position.checked_rem(segment).ok_or_else(overflow)?;
            let base = position.checked_sub(offset).ok_or_else(overflow)?;
            let room = segment.checked_sub(offset).ok_or_else(overflow)?;
            let take = usize::try_from(room).map_or(buf.len(), |room| room.min(buf.len()));
            if self.open.as_ref().is_none_or(|(open, _)| *open != base) {
                let name = format!("{LOG_RECORDING:016x}-{base:016x}.seg");
                self.open = Some((base, self.disk.open_read(&self.dir.join(name))?));
            }
            let (chunk, rest) = buf.split_at_mut(take);
            if let Some((_, file)) = &self.open {
                self.disk.read_at(file, offset, chunk)?;
            }
            position = position
                .checked_add(u64::try_from(take).map_err(|_| overflow())?)
                .ok_or_else(overflow)?;
            buf = rest;
        }
        Ok(())
    }
}

/// The bytes [`RaftLog::entries`] reads at once for frames the index
/// places back to back (karyos#1001).
const READ_WINDOW: u64 = 1 << 20;

/// `header`, checked against the index's `index` and `term` and a `span`
/// of bytes from `position`: exact unless `last` (karyos#904).
fn check_header(
    header: &[u8; FRAME_HEADER],
    index: u64,
    term: u64,
    position: u64,
    span: u64,
    last: bool,
) -> Result<Header, LogError> {
    let chain = |problem| LogError::Chain { position, problem };
    let frame = Header::decode(header).ok_or_else(|| chain(ChainProblem::Foreign))?;
    if frame.index != index {
        return Err(chain(ChainProblem::Index {
            expected: index,
            got: frame.index,
        }));
    }
    if frame.term != term {
        return Err(chain(ChainProblem::Term {
            expected: term,
            got: frame.term,
        }));
    }
    let claimed = u64::from(frame.length)
        .checked_add(FRAME_HEADER_LEN)
        .ok_or_else(|| chain(ChainProblem::PastEnd))?;
    if claimed > span || (!last && claimed != span) {
        return Err(chain(ChainProblem::Length { span, claimed }));
    }
    Ok(frame)
}

/// The frame's CRC-32C over its header's first 32 bytes and `payload`.
fn check_crc(
    header: &[u8; FRAME_HEADER],
    payload: &[u8],
    crc: u32,
    position: u64,
) -> Result<(), LogError> {
    let mut sum = Crc32c::new();
    sum.update(
        header
            .split_first_chunk::<32>()
            .map_or(&[][..], |(head, _)| head),
    );
    sum.update(payload);
    if sum.finish() != crc {
        return Err(LogError::Chain {
            position,
            problem: ChainProblem::Checksum,
        });
    }
    Ok(())
}

/// The entry a whole frame's bytes hold, checked as [`check_header`] and
/// [`check_crc`] do.
/// The entry slot `at` of `out`, pushed empty when `out` ends there: the
/// pool [`RaftLog::entries_into`] reuses.
fn pooled(out: &mut Vec<Entry>, at: usize) -> Result<&mut Entry, LogError> {
    if at >= out.len() {
        out.push(Entry {
            index: 0,
            term: 0,
            event_time: 0,
            payload: Vec::new(),
        });
    }
    out.get_mut(at)
        .ok_or(LogError::Store(SegmentError::PositionOverflow))
}

/// Checks `frame` as the entry `index` of `term` and writes it into
/// `entry`, reusing its payload buffer; `entry` is left unchanged when
/// the frame does not check.
fn check_frame_into(
    frame: &[u8],
    index: u64,
    term: u64,
    position: u64,
    last: bool,
    entry: &mut Entry,
) -> Result<(), LogError> {
    let span =
        u64::try_from(frame.len()).map_err(|_| LogError::Store(SegmentError::PositionOverflow))?;
    let Some((header, payload)) = frame.split_first_chunk::<FRAME_HEADER>() else {
        return Err(LogError::Chain {
            position,
            problem: ChainProblem::Length {
                span,
                claimed: FRAME_HEADER_LEN,
            },
        });
    };
    let decoded = check_header(header, index, term, position, span, last)?;
    let length = usize::try_from(decoded.length)
        .map_err(|_| LogError::Store(SegmentError::PositionOverflow))?;
    let payload = payload.get(..length).unwrap_or(payload);
    check_crc(header, payload, decoded.crc, position)?;
    entry.index = decoded.index;
    entry.term = decoded.term;
    entry.event_time = decoded.event_time;
    entry.payload.clear();
    entry.payload.extend_from_slice(payload);
    Ok(())
}

/// What the frame walk found: the entries, and a torn tail to cut.
struct Walk {
    entries: Vec<(u64, u64)>,
    /// The torn frame's position and index.
    torn: Option<(u64, u64)>,
}

/// Walks the frames of `[start, written)`. A frame that runs past
/// `written` is the torn tail when the log ends at a segment's end (A2
/// splits a write only there); any other frame that is not the next one
/// is [`LogError::Chain`].
fn walk<D: Disk>(
    reader: &mut RawReader<'_, D>,
    (start, written): (u64, u64),
    (first_index, base_term): (u64, Option<u64>),
    geometry: Geometry,
) -> Result<Walk, LogError> {
    let mut entries = Vec::new();
    let mut position = start;
    let mut next = first_index;
    // After an install, the first frame's term is not below the base's.
    let mut last_term = base_term;
    let at_segment_end = written.is_multiple_of(geometry.segment_length());
    while position < written {
        let chain = |problem| LogError::Chain { position, problem };
        let torn = |next| {
            if at_segment_end {
                Ok(Walk {
                    entries: Vec::new(),
                    torn: Some((position, next)),
                })
            } else {
                Err(chain(ChainProblem::PastEnd))
            }
        };
        let header_end = position
            .checked_add(FRAME_HEADER_LEN)
            .ok_or_else(|| chain(ChainProblem::PastEnd))?;
        if header_end > written {
            let cut = torn(next)?;
            return Ok(Walk {
                entries,
                torn: cut.torn,
            });
        }
        let mut header = [0u8; FRAME_HEADER];
        reader.read(position, &mut header)?;
        let frame = Header::decode(&header).ok_or_else(|| chain(ChainProblem::Foreign))?;
        let end = frame
            .end(position)
            .ok_or_else(|| chain(ChainProblem::PastEnd))?;
        if end > written {
            let cut = torn(next)?;
            return Ok(Walk {
                entries,
                torn: cut.torn,
            });
        }
        let length = usize::try_from(frame.length).map_err(|_| chain(ChainProblem::PastEnd))?;
        let mut payload = vec![0u8; length];
        reader.read(header_end, &mut payload)?;
        let mut crc = Crc32c::new();
        crc.update(
            header
                .split_first_chunk::<32>()
                .map_or(&[][..], |(head, _)| head),
        );
        crc.update(&payload);
        if crc.finish() != frame.crc {
            return Err(chain(ChainProblem::Checksum));
        }
        if frame.index != next {
            return Err(chain(ChainProblem::Index {
                expected: next,
                got: frame.index,
            }));
        }
        if let Some(last) = last_term.filter(|last| frame.term < *last) {
            return Err(chain(ChainProblem::TermBack {
                last,
                got: frame.term,
            }));
        }
        entries.push((position, frame.term));
        last_term = Some(frame.term);
        next = next
            .checked_add(1)
            .ok_or(LogError::TooLarge { index: next })?;
        position = end;
    }
    Ok(Walk {
        entries,
        torn: None,
    })
}
