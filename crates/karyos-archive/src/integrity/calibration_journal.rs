// SPDX-License-Identifier: Apache-2.0

//! The calibration journal on disk (ADR-0098 items 3 and 5;
//! quantstratum-docs: karyos/design/trace-clocks.md; karyos#1137): the
//! records the calibration producers (karyos#749, `karyos-tools calibrate`)
//! append, which a running Archive agent reads as its
//! [`CalibrationSource`].
//!
//! The design names the journal (`--archive-calibration-journal <path>`)
//! and its records (18 words, told apart by word 0's low byte,
//! [`ClockRecord`]), not a file layout. The layout is the Archive's own,
//! unchanged: the journal is a directory holding one [`SegmentStore`]
//! recording, [`RECORDING`], with the time evidence entries' geometry and
//! sync policy (`time_evidence`), one write per record of
//! [`RECORD_LENGTH`] bytes, each covered by its index entry's CRC-32C,
//! made durable by an explicit sync before the append returns. So:
//! - a torn tail (a record whose data or index entry a crash cut short)
//!   is past `written` and never read; the next writer's recovery cuts
//!   it ([`SegmentStore::recover`]), and a reader skips it until it is
//!   whole ([`SegmentStore::open_verified`], changing nothing);
//! - damage before the tail is the store's typed refusal, never misread;
//! - a record type this build does not know is kept and skipped by the
//!   reader ([`ClockRecord`]); a known type that does not decode is
//!   refused by the writer.
//!
//! One writer at a time: it holds an exclusive lock on [`LOCK_FILE`] in
//! the directory (the `flock` the integrity journal takes on its file),
//! so two producers never append over each other. Readers take no lock.

use std::path::{Path, PathBuf};

use karyos_trace::clocks::CALIBRATION_WORDS;
use karyos_trace::clocks::record::{ClockRecord, ClockRecordError};

use super::time_producer::{CalibrationSource, Snapshot};
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

/// The journal's store geometry, the time evidence entries' own: a record
/// never spans more than a write.
fn geometry() -> Result<Geometry, SegmentError> {
    Geometry::with_default_length(1 << 20)
}

/// Why the journal could not be written or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The journal's store failed, or refused damage before its tail.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Another writer holds the journal's lock. Nothing was written.
    #[error("the calibration journal is open by another writer")]
    Locked,
    /// A record of a known type that does not decode: never appended.
    #[error(transparent)]
    Record(#[from] ClockRecordError),
}

/// The journal's single writer.
#[derive(Debug)]
pub struct CalibrationJournal<D: Disk> {
    store: SegmentStore<D>,
    /// Held while the writer lives.
    _lock: D::File,
}

impl<D: Disk + Clone> CalibrationJournal<D> {
    /// Opens the journal in `dir`, which the caller made, recovering it
    /// (a torn tail cut), or makes it empty.
    ///
    /// # Errors
    ///
    /// [`JournalError::Locked`], and the store's refusals.
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
        let store = match SegmentStore::recover(
            disk.clone(),
            dir,
            RECORDING,
            geometry,
            SyncPolicy::PerSegment,
        ) {
            Ok(recovered) => recovered.store,
            Err(SegmentError::NotFound { .. }) => {
                SegmentStore::create(disk, dir, RECORDING, geometry, SyncPolicy::PerSegment, 0)?
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self { store, _lock: lock })
    }

    /// Appends `words`, durable on return; returns its position.
    ///
    /// # Errors
    ///
    /// [`JournalError::Record`] for a known type that does not decode
    /// (nothing written), and the store's errors.
    pub fn append(&mut self, words: &[u64; CALIBRATION_WORDS]) -> Result<u64, JournalError> {
        let _ = ClockRecord::decode(words)?;
        let mut bytes = [0u8; RECORD_LENGTH];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        let at = self.store.written();
        let _ = self.store.append(at, &bytes)?;
        let _ = self.store.sync()?;
        Ok(at)
    }
}

/// A journal's records, read once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    /// Every whole record, in order, of every type.
    pub records: Vec<[u64; CALIBRATION_WORDS]>,
    /// False when the store reports a loss: a gap, or a start past 0.
    pub lossless: bool,
}

/// Reads the journal in `dir` as its writer's recovery would leave it,
/// changing nothing: a torn tail is left out. A missing journal reads as
/// no records, lossless.
///
/// # Errors
///
/// The store's refusals of damage before its tail, and the operating
/// system's errors.
pub fn read<D: Disk>(disk: D, dir: &Path) -> Result<Records, JournalError> {
    let geometry = geometry()?;
    let mut store = match SegmentStore::open_verified(
        ReadOnly(disk),
        dir,
        RECORDING,
        geometry,
        SyncPolicy::None,
    ) {
        Ok(store) => store,
        Err(SegmentError::NotFound { .. }) => {
            return Ok(Records {
                records: Vec::new(),
                lossless: true,
            });
        }
        Err(SegmentError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Records {
                records: Vec::new(),
                lossless: true,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let length = RECORD_LENGTH as u64;
    let lossless = store.start() == 0 && store.gaps().is_empty();
    let mut records = Vec::new();
    let mut at = store.start();
    let mut bytes = [0u8; RECORD_LENGTH];
    while at.saturating_add(length) <= store.written() {
        store.read(at, &mut bytes)?;
        let mut words = [0u64; CALIBRATION_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        records.push(words);
        at = at.saturating_add(length);
    }
    Ok(Records { records, lossless })
}

/// The Archive agent's view of a calibration journal on disk: each
/// snapshot reads the journal again, so records appended while the agent
/// runs are seen.
#[derive(Debug)]
pub struct JournalSource<D> {
    disk: D,
    dir: PathBuf,
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
            Ok(records) => {
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
