// SPDX-License-Identifier: Apache-2.0

//! The durable Raft log and its term and vote store (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C4), core neutral, over the
//! Archive's segment store (A2).
//!
//! - **Frames.** Each entry is one A2 write, so every entry starts at a
//!   write boundary and a suffix can be cut there: a 36-byte header
//!   (magic `KRLE`, payload length, index, term, event time, CRC-32C of
//!   the header's first 32 bytes and the payload), then the payload.
//! - **Index.** The entry-to-byte index is kept in memory and rebuilt at
//!   [`RaftLog::open`] from the frames: there is no index file.
//! - **Positions.** `written` and `durable` are A2's, and their last
//!   entries are [`RaftLog::last_index`] and [`RaftLog::durable_index`];
//!   [`RaftLog::append`] advances only the first, [`RaftLog::sync`] the
//!   second. Commit and applied indices are the caller's.
//! - **Recovery.** [`RaftLog::open`] runs A2's recovery, which keeps every
//!   whole, checked write, then walks the frames. A frame the recovered
//!   bytes end inside (an entry whose later chunk was lost with its
//!   segment) is the torn tail: the log is cut at its start. Any other
//!   frame that is not the next one is refused, typed: a foreign magic, a
//!   CRC failure, an index that does not follow, a term that goes back.
//! - **Hard state.** [`HardState`] lives in its own file, replaced
//!   atomically; a failed save poisons the log until it is reopened.
//! - **First index.** Kept in its own file, written at creation, so an
//!   emptied log keeps it. Purging a prefix waits for snapshots (C8).
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
//!    index: the reopened commit is never above the recovered log.

use std::fmt;
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::Disk;
use karyos_archive::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

use crate::file;
use crate::hard_state::{HARD_STATE_FILE, HardState, HardStateProblem};

/// The A2 recording id of the log.
pub const LOG_RECORDING: u64 = 1;
/// The file keeping the log's first index.
pub const FIRST_INDEX_FILE: &str = "first-index";
/// A frame's header length.
pub const FRAME_HEADER: usize = 36;
const MAGIC: [u8; 4] = *b"KRLE";

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
        let mut frame = Vec::with_capacity(self.payload.len());
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&self.index.to_le_bytes());
        frame.extend_from_slice(&self.term.to_le_bytes());
        frame.extend_from_slice(&self.event_time.to_le_bytes());
        let mut crc = karyos_archive::crc32c::Crc32c::new();
        crc.update(&frame);
        crc.update(&self.payload);
        frame.extend_from_slice(&crc.finish().to_le_bytes());
        frame.extend_from_slice(&self.payload);
        Ok(frame)
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
        let word = |at: usize| -> Option<u64> {
            Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
        };
        let half = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        };
        if bytes.get(..4) != Some(&MAGIC[..]) {
            return None;
        }
        Some(Self {
            length: half(4)?,
            index: word(8)?,
            term: word(16)?,
            event_time: word(24)?,
            crc: half(32)?,
        })
    }
}

/// Why the log refuses an operation, or its files.
#[derive(Debug)]
pub enum LogError {
    /// An append that does not start right after the last index.
    NotNext {
        /// The index it must start at.
        expected: u64,
        /// The index it started at.
        got: u64,
    },
    /// An append whose term is below the last entry's.
    TermBack {
        /// The entry's index.
        index: u64,
        /// The last term.
        last: u64,
        /// The entry's term.
        got: u64,
    },
    /// A payload over `u32::MAX` bytes.
    TooLarge {
        /// The entry's index.
        index: u64,
    },
    /// A truncation outside `[first_index, last_index + 1]`.
    OutOfRange {
        /// The index asked for.
        index: u64,
        /// The first index.
        first: u64,
        /// The last index.
        last: u64,
    },
    /// Purging a prefix waits for snapshots (C8).
    PurgeUnsupported,
    /// A truncation that would remove an entry at or below the stored
    /// commit: committed entries are never removed.
    TruncateBelowCommit {
        /// The first index the truncation would remove.
        from: u64,
        /// The stored commit.
        commit: u64,
    },
    /// A frame found at recovery that does not continue the chain.
    Chain {
        /// The frame's position.
        position: u64,
        /// What is wrong.
        problem: ChainProblem,
    },
    /// The first-index file is missing or not one this version wrote.
    FirstIndex,
    /// The hard-state record is refused.
    HardState(HardStateProblem),
    /// A commit index above the durable last index.
    CommitBeyondDurable {
        /// The commit asked for.
        commit: u64,
        /// The durable last index.
        durable: u64,
    },
    /// A log sync or a hard-state save failed earlier: writes are refused
    /// until the log is reopened.
    Poisoned,
    /// The segment store's error.
    Store(SegmentError),
    /// The disk's error.
    Io(io::Error),
}

/// What is wrong with a frame at recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProblem {
    /// Not a frame: another magic.
    Foreign,
    /// Its CRC does not match.
    Checksum,
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
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNext { expected, got } => {
                write!(f, "an append at index {got}; the next index is {expected}")
            }
            Self::TermBack { index, last, got } => {
                write!(
                    f,
                    "entry {index} has term {got}, below the last term {last}"
                )
            }
            Self::TooLarge { index } => write!(f, "entry {index}'s payload is too large"),
            Self::OutOfRange { index, first, last } => {
                write!(f, "index {index} is outside [{first}, {last} + 1]")
            }
            Self::PurgeUnsupported => f.write_str("purging a prefix waits for snapshots"),
            Self::TruncateBelowCommit { from, commit } => {
                write!(
                    f,
                    "truncating from {from} would remove committed entries up to {commit}"
                )
            }
            Self::Chain { position, problem } => {
                write!(f, "the frame at {position} breaks the chain: {problem:?}")
            }
            Self::FirstIndex => f.write_str("the first-index file is missing or invalid"),
            Self::HardState(problem) => write!(f, "the hard state is refused: {problem}"),
            Self::CommitBeyondDurable { commit, durable } => {
                write!(
                    f,
                    "commit {commit} is above the durable last index {durable}"
                )
            }
            Self::Poisoned => f.write_str("a sync or a save failed: reopen the log"),
            Self::Store(error) => write!(f, "segment store: {error}"),
            Self::Io(error) => write!(f, "disk: {error}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<SegmentError> for LogError {
    fn from(error: SegmentError) -> Self {
        Self::Store(error)
    }
}

impl From<io::Error> for LogError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
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
    hard_state: Option<HardState>,
    poisoned: bool,
}

/// What [`RaftLog::open`] found.
#[derive(Debug)]
pub struct Opened<D: Disk + Clone> {
    /// The log.
    pub log: RaftLog<D>,
    /// The position recovery cut a torn tail at, if it did.
    pub cut: Option<u64>,
}

fn encode_first(first: u64) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&first.to_le_bytes());
    bytes[8..].copy_from_slice(&crc32c(&first.to_le_bytes()).to_le_bytes());
    bytes
}

fn decode_first(bytes: &[u8]) -> Option<u64> {
    let first = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    let crc = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    (bytes.len() == 12 && crc == crc32c(&first.to_le_bytes())).then_some(first)
}

impl<D: Disk + Clone> RaftLog<D> {
    /// Creates an empty log in `dir`, whose first entry will be
    /// `first_index`.
    ///
    /// # Errors
    ///
    /// The store's errors ([`SegmentError::Exists`] when a log is there),
    /// and the disk's.
    pub fn create(
        mut disk: D,
        dir: &Path,
        geometry: Geometry,
        first_index: u64,
    ) -> Result<Self, LogError> {
        let store = SegmentStore::create(
            disk.clone(),
            dir,
            LOG_RECORDING,
            geometry,
            SyncPolicy::PerSegment,
            0,
        )?;
        file::replace(&mut disk, dir, FIRST_INDEX_FILE, &encode_first(first_index))?;
        Ok(Self {
            store,
            disk,
            dir: dir.to_path_buf(),
            first_index,
            entries: Vec::new(),
            hard_state: None,
            poisoned: false,
        })
    }

    /// Opens the log in `dir` after a crash or a close: recovers the store,
    /// rebuilds the index from the frames, cuts a torn tail, and loads the
    /// hard state.
    ///
    /// # Errors
    ///
    /// [`LogError::Chain`] for a frame that does not continue the chain,
    /// [`LogError::FirstIndex`], [`LogError::HardState`] for a refused
    /// record, [`LogError::CommitBeyondDurable`] for a stored commit above
    /// the recovered log, and the store's and the disk's errors.
    pub fn open(mut disk: D, dir: &Path, geometry: Geometry) -> Result<Opened<D>, LogError> {
        let first_index = file::read(&mut disk, dir, FIRST_INDEX_FILE)?
            .as_deref()
            .and_then(decode_first)
            .ok_or(LogError::FirstIndex)?;
        let recovered = SegmentStore::recover(
            disk.clone(),
            dir,
            LOG_RECORDING,
            geometry,
            SyncPolicy::PerSegment,
        )?;
        let mut log = Self {
            store: recovered.store,
            disk,
            dir: dir.to_path_buf(),
            first_index,
            entries: Vec::new(),
            hard_state: None,
            poisoned: false,
        };
        let cut = log.rebuild()?;
        log.hard_state = match file::read(&mut log.disk, dir, HARD_STATE_FILE)? {
            Some(bytes) => Some(HardState::decode(&bytes).map_err(LogError::HardState)?),
            None => None,
        };
        if let Some(commit) = log.hard_state.and_then(|state| state.commit) {
            log.check_commit(commit)?;
        }
        Ok(Opened { log, cut })
    }

    /// Walks the frames from the start; returns where a torn tail was cut.
    fn rebuild(&mut self) -> Result<Option<u64>, LogError> {
        let written = self.store.written();
        let mut position = self.store.start();
        let mut next = self.first_index;
        let mut last_term = 0;
        while position < written {
            let mut header = [0u8; FRAME_HEADER];
            let header_end = position.checked_add(FRAME_HEADER as u64);
            if header_end.is_none_or(|end| end > written) {
                return self.cut_tail(position);
            }
            self.store.read(position, &mut header)?;
            let chain = |problem| LogError::Chain { position, problem };
            let frame = Header::decode(&header).ok_or_else(|| chain(ChainProblem::Foreign))?;
            let end = header_end
                .and_then(|end| end.checked_add(u64::from(frame.length)))
                .ok_or_else(|| chain(ChainProblem::Checksum))?;
            if end > written {
                return self.cut_tail(position);
            }
            let mut payload = vec![0u8; usize::try_from(frame.length).unwrap_or(0)];
            let payload_at = header_end.unwrap_or(position);
            self.store.read(payload_at, &mut payload)?;
            let mut crc = karyos_archive::crc32c::Crc32c::new();
            crc.update(header.get(..32).unwrap_or(&[]));
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
            if frame.term < last_term {
                return Err(chain(ChainProblem::TermBack {
                    last: last_term,
                    got: frame.term,
                }));
            }
            self.entries.push((position, frame.term));
            last_term = frame.term;
            next = next.checked_add(1).ok_or_else(|| {
                chain(ChainProblem::Index {
                    expected: next,
                    got: frame.index,
                })
            })?;
            position = end;
        }
        Ok(None)
    }

    fn cut_tail(&mut self, position: u64) -> Result<Option<u64>, LogError> {
        self.store.truncate(position)?;
        Ok(Some(position))
    }

    /// The first index.
    #[must_use]
    pub fn first_index(&self) -> u64 {
        self.first_index
    }

    /// The last index written, or `first_index - 1` when empty.
    #[must_use]
    pub fn last_index(&self) -> u64 {
        self.index_of(self.entries.len())
    }

    /// The index of the `count`th entry from the first, or the one before
    /// the first for 0.
    fn index_of(&self, count: usize) -> u64 {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        self.first_index
            .checked_add(count)
            .and_then(|next| next.checked_sub(1))
            .unwrap_or(0)
    }

    /// The last index whose whole frame is durable.
    #[must_use]
    pub fn durable_index(&self) -> u64 {
        let durable = self.store.durable();
        let ends = self.entries.iter().skip(1).map(|(start, _)| *start);
        let kept = self
            .entries
            .iter()
            .zip(ends.chain(std::iter::once(self.store.written())))
            .take_while(|(_, end)| *end <= durable)
            .count();
        self.index_of(kept)
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

    /// Appends `entries`, each starting right after the last index and not
    /// lowering the term; returns the last index written. Not durable
    /// until [`RaftLog::sync`].
    ///
    /// # Errors
    ///
    /// [`LogError::NotNext`], [`LogError::TermBack`] and
    /// [`LogError::TooLarge`], checked for every entry before anything is
    /// written; [`LogError::Poisoned`]; the store's errors.
    pub fn append(&mut self, entries: &[Entry]) -> Result<u64, LogError> {
        self.check_writable()?;
        let mut expected = self.last_index().checked_add(1).ok_or(LogError::NotNext {
            expected: u64::MAX,
            got: u64::MAX,
        })?;
        let mut last = self.entries.last().map_or(0, |(_, term)| *term);
        let mut frames = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.index != expected {
                return Err(LogError::NotNext {
                    expected,
                    got: entry.index,
                });
            }
            if entry.term < last {
                return Err(LogError::TermBack {
                    index: entry.index,
                    last,
                    got: entry.term,
                });
            }
            frames.push((entry.term, entry.frame()?));
            last = entry.term;
            expected = expected
                .checked_add(1)
                .ok_or(LogError::TooLarge { index: entry.index })?;
        }
        for (term, frame) in frames {
            let position = self.store.written();
            self.store.append(position, &frame)?;
            self.entries.push((position, term));
        }
        Ok(self.last_index())
    }

    /// Makes every written entry durable; returns the durable last index.
    ///
    /// # Errors
    ///
    /// [`LogError::Poisoned`]; the store's errors, which poison the log:
    /// every later write is refused with [`LogError::Poisoned`] until it is
    /// reopened.
    pub fn sync(&mut self) -> Result<u64, LogError> {
        self.check_writable()?;
        if let Err(error) = self.store.sync() {
            self.poisoned = true;
            return Err(LogError::Store(error));
        }
        Ok(self.durable_index())
    }

    /// Removes entry `from_index` and every later one; appends restart at
    /// `from_index`. What is kept is durable on return.
    ///
    /// # Errors
    ///
    /// [`LogError::OutOfRange`] outside `[first_index, last_index + 1]`
    /// and [`LogError::TruncateBelowCommit`] at or below the stored
    /// commit, which change nothing; [`LogError::Poisoned`]; the store's
    /// errors.
    pub fn truncate_suffix(&mut self, from_index: u64) -> Result<(), LogError> {
        self.check_writable()?;
        if let Some(commit) = self.hard_state.and_then(|state| state.commit)
            && from_index <= commit
        {
            return Err(LogError::TruncateBelowCommit {
                from: from_index,
                commit,
            });
        }
        let out = LogError::OutOfRange {
            index: from_index,
            first: self.first_index,
            last: self.last_index(),
        };
        let slot = self.slot(from_index).ok_or(out)?;
        let position = match self.entries.get(slot) {
            Some((position, _)) => *position,
            None if slot == self.entries.len() => return Ok(()),
            None => {
                return Err(LogError::OutOfRange {
                    index: from_index,
                    first: self.first_index,
                    last: self.last_index(),
                });
            }
        };
        self.store.truncate(position)?;
        self.entries.truncate(slot);
        Ok(())
    }

    /// Purging a prefix waits for snapshots (C8).
    ///
    /// # Errors
    ///
    /// Always [`LogError::PurgeUnsupported`].
    pub fn purge_prefix(&mut self, _below: u64) -> Result<(), LogError> {
        Err(LogError::PurgeUnsupported)
    }

    /// The entries of `range` the log holds, in order, stopping before the
    /// one that would take the payloads past `max_bytes`; the first is
    /// returned whatever its size, so a range is never refused.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn entries(&mut self, range: Range<u64>, max_bytes: u64) -> Result<Vec<Entry>, LogError> {
        let mut found = Vec::new();
        let mut bytes = 0u64;
        for index in range {
            let Some(&(position, _)) = self.slot(index).and_then(|slot| self.entries.get(slot))
            else {
                break;
            };
            let mut header = [0u8; FRAME_HEADER];
            self.store.read(position, &mut header)?;
            let frame = Header::decode(&header).ok_or(LogError::Chain {
                position,
                problem: ChainProblem::Foreign,
            })?;
            // Past `max_bytes` (or past `u64`), only the first is kept.
            let total = bytes.checked_add(u64::from(frame.length));
            let Some(total) = total.filter(|total| found.is_empty() || *total <= max_bytes) else {
                break;
            };
            let mut payload = vec![0u8; usize::try_from(frame.length).unwrap_or(0)];
            let at = position
                .checked_add(FRAME_HEADER as u64)
                .ok_or(LogError::Store(SegmentError::PositionOverflow))?;
            self.store.read(at, &mut payload)?;
            found.push(Entry {
                index: frame.index,
                term: frame.term,
                event_time: frame.event_time,
                payload,
            });
            bytes = total;
        }
        Ok(found)
    }

    /// The stored hard state, if any was saved.
    #[must_use]
    pub fn hard_state(&self) -> Option<HardState> {
        self.hard_state
    }

    fn check_commit(&self, commit: u64) -> Result<(), LogError> {
        let durable = self.durable_index();
        if commit > durable {
            return Err(LogError::CommitBeyondDurable { commit, durable });
        }
        Ok(())
    }

    /// Saves `state` durably: returns only after its sync. A failure
    /// poisons the log, which refuses every write until reopened.
    ///
    /// # Errors
    ///
    /// [`LogError::CommitBeyondDurable`], which changes nothing;
    /// [`LogError::Poisoned`]; the disk's errors, which poison.
    pub fn save_hard_state(&mut self, state: HardState) -> Result<(), LogError> {
        self.check_writable()?;
        if let Some(commit) = state.commit {
            self.check_commit(commit)?;
        }
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
}
