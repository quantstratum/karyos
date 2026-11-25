// SPDX-License-Identifier: Apache-2.0

//! The calibration journal on disk (ADR-0098 items 3 and 5; ADR-0110;
//! quantstratum-docs: karyos/design/trace-clocks.md; karyos#1137): the
//! records the calibration producers (karyos#749, `karyos-tools calibrate`)
//! append, which a running Archive agent reads as its
//! [`CalibrationSource`].
//!
//! A journal is a directory:
//! - one [`SegmentStore`] recording, [`RECORDING`], one write per record
//!   of [`RECORD_LENGTH`] bytes, each covered by its index entry's
//!   CRC-32C. The segment length is a multiple of [`RECORD_LENGTH`], so a
//!   record never straddles two segments;
//! - [`DURABLE_FILE`], the committed position and the journal's
//!   generation with their CRC-32C, replaced atomically (written to
//!   [`DURABLE_TEMP`], synced, renamed, the directory synced) only after
//!   the store's sync. A record past it was never committed: it is
//!   invisible to readers, and the next writer cuts it;
//! - [`LOCK_FILE`], the single writer's `flock`.
//!
//! A reader reads [`DURABLE_FILE`] first, then the store verified, and
//! takes only the prefix up to the committed position. A store shorter
//! than that position (a cut before the tail, a truncation) is a loss,
//! never a shorter lossless journal. The generation, written at creation,
//! never changes: rotating means a new directory, and a source that sees
//! another generation reports a loss.
//!
//! The writer keeps ADR-0098's completeness boundary: under its lock it
//! refuses a record whose `valid_from` is not after the last stored
//! record of the same type and the same clock, skips one byte-identical
//! to a stored record ("already present", so a retried batch never
//! duplicates), and appends nothing of a batch any record of which is
//! refused. A record type this build does not know is appended unchecked
//! and skipped by readers ([`ClockRecord`]).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use karyos_trace::clocks::record::{ClockRecord, ClockRecordError};
use karyos_trace::clocks::{CALIBRATION_WORDS, ClockKey};

use super::time_producer::{CalibrationSource, Snapshot};
use crate::crc32c::crc32c;
use crate::disk::{Disk, ReadOnly};
use crate::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

#[cfg(test)]
mod tests;

/// The records' recording id in the journal's store.
pub const RECORDING: u64 = 1;
/// A record's length in bytes: 18 little-endian words.
pub const RECORD_LENGTH: usize = CALIBRATION_WORDS * 8;
/// The writer's lock file in the journal directory.
pub const LOCK_FILE: &str = "writer.lock";
/// The committed position's file in the journal directory.
pub const DURABLE_FILE: &str = "durable";
/// Its replacement, before the rename.
pub const DURABLE_TEMP: &str = "durable.tmp";
/// The committed position file's length: generation, position, CRC-32C.
const DURABLE_LENGTH: usize = 20;
/// Records per term: a term of about 1 MiB.
#[cfg(not(test))]
const TERM_RECORDS: u32 = 7281;
/// Terms per segment: a segment of about 128 MiB.
#[cfg(not(test))]
const SEGMENT_TERMS: u64 = 128;
/// Tests cross segments within a few records.
#[cfg(test)]
const TERM_RECORDS: u32 = 4;
#[cfg(test)]
const SEGMENT_TERMS: u64 = 2;

/// The journal's store geometry: terms and segments whole multiples of a
/// record, so no record crosses a segment.
fn geometry() -> Result<Geometry, SegmentError> {
    let term = u32::try_from(RECORD_LENGTH)
        .ok()
        .and_then(|length| TERM_RECORDS.checked_mul(length))
        .ok_or(SegmentError::InvalidGeometry)?;
    Geometry::new(term, u64::from(term).saturating_mul(SEGMENT_TERMS))
}

/// Why the journal could not be written or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The journal's store failed, or refused damage.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Another writer holds the journal's lock. Nothing was written.
    #[error("the calibration journal is open by another writer")]
    Locked,
    /// The committed position file does not decode, or the store does not
    /// hold every record it commits: the journal lost records. A writer
    /// never repairs it.
    #[error("the calibration journal is damaged: {0}")]
    Damaged(&'static str),
    /// Records of the batch were refused; nothing of it was appended.
    #[error("{} record(s) refused, none appended", .0.len())]
    Refused(Vec<(usize, Refusal)>),
    /// An earlier append failed part way; reopen the journal to recover.
    #[error("an earlier append failed; the journal must be reopened")]
    Poisoned,
}

/// Why one record of a batch is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// A known type that does not decode.
    #[error(transparent)]
    Record(#[from] ClockRecordError),
    /// Its `valid_from` is not after the last stored record's of the same
    /// type and clock: the producer would move its completeness boundary
    /// back.
    #[error("valid_from {valid_from} is not after {last}, the last of its type and clock")]
    OutOfOrder {
        /// The record's.
        valid_from: u64,
        /// The last stored one's.
        last: u64,
    },
}

/// What became of one record of an accepted batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// Appended at this position.
    At(u64),
    /// Byte-identical to a stored record: skipped.
    AlreadyPresent,
}

/// The committed position and the journal's generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Durable {
    /// The journal directory's generation, fixed at its creation.
    pub generation: u64,
    /// The end of the committed records.
    pub position: u64,
}

impl Durable {
    fn encode(self) -> [u8; DURABLE_LENGTH] {
        let mut out = [0u8; DURABLE_LENGTH];
        let (head, crc) = out.split_at_mut(16);
        let (generation, position) = head.split_at_mut(8);
        generation.copy_from_slice(&self.generation.to_le_bytes());
        position.copy_from_slice(&self.position.to_le_bytes());
        let sum = crc32c(head);
        crc.copy_from_slice(&sum.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let damaged = JournalError::Damaged("its committed position does not decode");
        let Some((head, crc)) = bytes.split_first_chunk::<16>() else {
            return Err(damaged);
        };
        let Ok(crc) = <[u8; 4]>::try_from(crc) else {
            return Err(damaged);
        };
        if crc32c(head) != u32::from_le_bytes(crc) {
            return Err(damaged);
        }
        let (generation, position) = head.split_at(8);
        let word = |bytes: &[u8]| <[u8; 8]>::try_from(bytes).map(u64::from_le_bytes);
        let (Ok(generation), Ok(position)) = (word(generation), word(position)) else {
            return Err(damaged);
        };
        if generation == 0 || !position.is_multiple_of(RECORD_LENGTH as u64) {
            return Err(damaged);
        }
        Ok(Self {
            generation,
            position,
        })
    }
}

/// Reads the committed position of the journal in `dir`; `None` when the
/// journal was never made.
///
/// # Errors
///
/// [`JournalError::Damaged`], and the operating system's errors.
pub fn read_durable<D: Disk>(disk: &mut D, dir: &Path) -> Result<Option<Durable>, JournalError> {
    let file = match disk.open_read(&dir.join(DURABLE_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let length = disk.len(&file)?;
    if length != DURABLE_LENGTH as u64 {
        return Err(JournalError::Damaged(
            "its committed position does not decode",
        ));
    }
    let mut bytes = [0u8; DURABLE_LENGTH];
    disk.read_at(&file, 0, &mut bytes)?;
    Durable::decode(&bytes).map(Some)
}

/// Replaces the committed position atomically: the temporary file written
/// and synced, renamed over it, the directory synced.
fn write_durable<D: Disk>(disk: &mut D, dir: &Path, durable: Durable) -> std::io::Result<()> {
    let temp = dir.join(DURABLE_TEMP);
    let file = disk.create(&temp)?;
    disk.write_at(&file, 0, &durable.encode())?;
    disk.sync(&file)?;
    drop(file);
    disk.rename(&temp, &dir.join(DURABLE_FILE))?;
    disk.sync_dir(dir)
}

/// A new journal's generation: the creation time in nanoseconds mixed
/// with the process id, never 0.
fn new_generation() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let low = u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0);
    let mixed = low ^ (u64::from(std::process::id()) << 48);
    mixed.max(1)
}

/// The ordering key of a known record: its type and clock, and its
/// `valid_from`.
fn ordering(record: &ClockRecord) -> Option<((u8, ClockKey), u64)> {
    match record {
        ClockRecord::Calibration(calibration) => {
            Some(((1, calibration.from), calibration.valid_from))
        }
        ClockRecord::UtcReference(reference) => Some(((2, reference.clock), reference.valid_from)),
        _ => None,
    }
}

/// Reads the store's records in `[0, end)`, whole records only.
fn records_until<D: Disk>(
    store: &mut SegmentStore<D>,
    end: u64,
) -> Result<Vec<[u64; CALIBRATION_WORDS]>, SegmentError> {
    let length = RECORD_LENGTH as u64;
    let mut records = Vec::new();
    let mut at = store.start();
    let mut bytes = [0u8; RECORD_LENGTH];
    while at.saturating_add(length) <= end.min(store.written()) {
        store.read(at, &mut bytes)?;
        let mut words = [0u64; CALIBRATION_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        records.push(words);
        at = at.saturating_add(length);
    }
    Ok(records)
}

/// The journal's single writer.
#[derive(Debug)]
pub struct CalibrationJournal<D: Disk> {
    disk: D,
    dir: PathBuf,
    store: SegmentStore<D>,
    durable: Durable,
    /// Every committed record, for the duplicate check.
    stored: HashSet<[u64; CALIBRATION_WORDS]>,
    /// The last committed `valid_from` per type and clock.
    last: HashMap<(u8, ClockKey), u64>,
    poisoned: bool,
    /// Held while the writer lives.
    _lock: D::File,
}

impl<D: Disk + Clone> CalibrationJournal<D> {
    /// Opens the journal in `dir`, which the caller made, or makes it
    /// empty with a new generation. Records past the committed position
    /// (a batch whose commit a crash cut short) are cut.
    ///
    /// # Errors
    ///
    /// [`JournalError::Locked`], [`JournalError::Damaged`] when the store
    /// does not hold every committed record, and the store's refusals.
    pub fn open(disk: D, dir: &Path) -> Result<Self, JournalError> {
        let mut locker = disk.clone();
        let path = dir.join(LOCK_FILE);
        let lock = match locker.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match locker.create_new(&path) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        locker.open(&path)?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
        locker.lock(&lock).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                JournalError::Locked
            } else {
                JournalError::Io(error)
            }
        })?;
        let geometry = geometry()?;
        let durable = read_durable(&mut locker, dir)?;
        // Checked before recovery cuts anything: a store that does not
        // hold every committed record is left as it is, for inspection.
        if let Some(committed) = durable.filter(|durable| durable.position > 0) {
            let plan = SegmentStore::verify(disk.clone(), dir, RECORDING, geometry)?;
            if plan
                .kept
                .is_none_or(|kept| kept.written < committed.position)
            {
                return Err(JournalError::Damaged(
                    "its store does not hold every committed record",
                ));
            }
        }
        let mut store = match SegmentStore::recover(
            disk.clone(),
            dir,
            RECORDING,
            geometry,
            SyncPolicy::PerSegment,
        ) {
            Ok(recovered) => recovered.store,
            Err(SegmentError::NotFound { .. }) if durable.is_none_or(|d| d.position == 0) => {
                SegmentStore::create(
                    disk.clone(),
                    dir,
                    RECORDING,
                    geometry,
                    SyncPolicy::PerSegment,
                    0,
                )?
            }
            Err(SegmentError::NotFound { .. }) => {
                return Err(JournalError::Damaged("its store holds no committed record"));
            }
            Err(error) => return Err(error.into()),
        };
        let durable = match durable {
            Some(durable) => durable,
            None => {
                // Never committed: whatever a crash left in the store
                // before the first commit was never visible.
                let fresh = Durable {
                    generation: new_generation(),
                    position: 0,
                };
                if store.written() > 0 {
                    let _ = store.truncate(0)?;
                }
                write_durable(&mut locker, dir, fresh)?;
                fresh
            }
        };
        if store.start() != 0 || !store.gaps().is_empty() || store.written() < durable.position {
            return Err(JournalError::Damaged(
                "its store does not hold every committed record",
            ));
        }
        if store.written() > durable.position {
            let _ = store.truncate(durable.position)?;
        }
        let records = records_until(&mut store, durable.position)?;
        let mut stored = HashSet::with_capacity(records.len());
        let mut last = HashMap::new();
        for words in &records {
            let _ = stored.insert(*words);
            if let Some((key, valid_from)) =
                ClockRecord::decode(words).ok().as_ref().and_then(ordering)
            {
                let entry = last.entry(key).or_insert(valid_from);
                *entry = (*entry).max(valid_from);
            }
        }
        Ok(Self {
            disk: locker,
            dir: dir.to_path_buf(),
            store,
            durable,
            stored,
            last,
            poisoned: false,
            _lock: lock,
        })
    }

    /// The committed position and generation.
    #[must_use]
    pub const fn durable(&self) -> Durable {
        self.durable
    }

    /// Appends one record: [`CalibrationJournal::append_batch`] of one.
    ///
    /// # Errors
    ///
    /// As [`CalibrationJournal::append_batch`].
    pub fn append(&mut self, words: &[u64; CALIBRATION_WORDS]) -> Result<Appended, JournalError> {
        let mut outcomes = self.append_batch(core::slice::from_ref(words))?;
        outcomes.pop().ok_or(JournalError::Poisoned)
    }

    /// Appends `records` in order, all or none: every record is checked
    /// first (a known type that does not decode, or a `valid_from` not
    /// after the last of its type and clock, refuses the batch); one
    /// byte-identical to a stored record, or to an earlier one of the
    /// batch, is skipped. Then the new records are written, the store
    /// synced, and the committed position replaced: only then are they
    /// visible.
    ///
    /// # Errors
    ///
    /// [`JournalError::Refused`] with every refusal (nothing written),
    /// [`JournalError::Poisoned`] after an earlier failure, and the
    /// store's or the operating system's errors, after which nothing of
    /// the batch is committed and the journal must be reopened.
    pub fn append_batch(
        &mut self,
        records: &[[u64; CALIBRATION_WORDS]],
    ) -> Result<Vec<Appended>, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        let mut last = self.last.clone();
        let mut seen = HashSet::new();
        let mut refused = Vec::new();
        let mut fresh = Vec::new();
        for (index, words) in records.iter().enumerate() {
            if self.stored.contains(words) || !seen.insert(*words) {
                continue;
            }
            match ClockRecord::decode(words) {
                Err(error) => refused.push((index, Refusal::Record(error))),
                Ok(record) => {
                    if let Some((key, valid_from)) = ordering(&record) {
                        match last.get(&key) {
                            Some(&previous) if valid_from <= previous => {
                                refused.push((
                                    index,
                                    Refusal::OutOfOrder {
                                        valid_from,
                                        last: previous,
                                    },
                                ));
                                continue;
                            }
                            _ => {
                                let _ = last.insert(key, valid_from);
                            }
                        }
                    }
                    fresh.push(index);
                }
            }
        }
        if !refused.is_empty() {
            return Err(JournalError::Refused(refused));
        }
        let mut outcomes = vec![Appended::AlreadyPresent; records.len()];
        if fresh.is_empty() {
            return Ok(outcomes);
        }
        let result = self.write(records, &fresh, &mut outcomes);
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        for &index in &fresh {
            if let Some(words) = records.get(index) {
                let _ = self.stored.insert(*words);
            }
        }
        self.last = last;
        Ok(outcomes)
    }

    fn write(
        &mut self,
        records: &[[u64; CALIBRATION_WORDS]],
        fresh: &[usize],
        outcomes: &mut [Appended],
    ) -> Result<(), JournalError> {
        for &index in fresh {
            let (Some(words), Some(outcome)) = (records.get(index), outcomes.get_mut(index)) else {
                return Err(JournalError::Poisoned);
            };
            let mut bytes = [0u8; RECORD_LENGTH];
            for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
                *chunk = word.to_le_bytes();
            }
            let at = self.store.written();
            let _ = self.store.append(at, &bytes)?;
            *outcome = Appended::At(at);
        }
        let _ = self.store.sync()?;
        let committed = Durable {
            generation: self.durable.generation,
            position: self.store.written(),
        };
        write_durable(&mut self.disk, &self.dir, committed)?;
        self.durable = committed;
        Ok(())
    }
}

/// A journal's committed records, read once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    /// The journal's generation; 0 for a journal never made.
    pub generation: u64,
    /// Every committed record that the store holds, in order, of every
    /// type.
    pub records: Vec<[u64; CALIBRATION_WORDS]>,
    /// False when the journal lost records: the store does not hold every
    /// committed record, has a gap, or starts past 0.
    pub lossless: bool,
}

/// Reads the journal in `dir`, changing nothing: its committed position
/// first, then the records up to it. A journal never made reads as no
/// records, lossless.
///
/// # Errors
///
/// [`JournalError::Damaged`] for a committed position that does not
/// decode, the store's refusals, and the operating system's errors.
pub fn read<D: Disk>(disk: D, dir: &Path) -> Result<Records, JournalError> {
    let mut probe = disk;
    let Some(durable) = read_durable(&mut probe, dir)? else {
        return Ok(Records {
            generation: 0,
            records: Vec::new(),
            lossless: true,
        });
    };
    let geometry = geometry()?;
    let mut store = match SegmentStore::open_verified(
        ReadOnly(probe),
        dir,
        RECORDING,
        geometry,
        SyncPolicy::None,
    ) {
        Ok(store) => store,
        Err(SegmentError::NotFound { .. }) => {
            return Ok(Records {
                generation: durable.generation,
                records: Vec::new(),
                lossless: durable.position == 0,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let lossless =
        store.start() == 0 && store.gaps().is_empty() && store.written() >= durable.position;
    let records = records_until(&mut store, durable.position)?;
    Ok(Records {
        generation: durable.generation,
        records,
        lossless,
    })
}

/// The Archive agent's view of a calibration journal on disk: each
/// snapshot reads the journal again, so records committed while the agent
/// runs are seen. One source reads one journal generation.
#[derive(Debug)]
pub struct JournalSource<D> {
    disk: D,
    dir: PathBuf,
    /// The generation of the first journal read; 0 before.
    generation: u64,
    /// The records of the last read. A read that fails (damage, or a
    /// writer's recovery racing it) gives them reporting a loss, so no
    /// range is proven from that snapshot; the agent's next snapshot
    /// reads again.
    last: Vec<[u64; CALIBRATION_WORDS]>,
    /// Reads that failed, for the host to report.
    failures: u64,
}

impl<D: Disk + Clone> JournalSource<D> {
    /// The journal in `dir`.
    #[must_use]
    pub fn new(disk: D, dir: &Path) -> Self {
        Self {
            disk,
            dir: dir.to_path_buf(),
            generation: 0,
            last: Vec::new(),
            failures: 0,
        }
    }

    /// Reads that failed so far.
    #[must_use]
    pub const fn failures(&self) -> u64 {
        self.failures
    }
}

impl<D: Disk + Clone + Send + core::fmt::Debug> CalibrationSource for JournalSource<D> {
    fn snapshot(&mut self) -> Snapshot {
        match read(self.disk.clone(), &self.dir) {
            Ok(records) if records.generation == 0 && self.generation == 0 => {
                Snapshot::new(&[], records.lossless)
            }
            Ok(records) => {
                if self.generation == 0 {
                    self.generation = records.generation;
                }
                if records.generation != self.generation {
                    // Another journal in the same path: not this source's.
                    self.failures = self.failures.saturating_add(1);
                    return Snapshot::new(&self.last, false);
                }
                let snapshot = Snapshot::new(&records.records, records.lossless);
                self.last = records.records;
                snapshot
            }
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                Snapshot::new(&self.last, false)
            }
        }
    }
}
