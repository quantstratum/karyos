// SPDX-License-Identifier: Apache-2.0

//! Time evidence entries (SPEC.md §8.4, "Time evidence"; ADR-0095;
//! quantstratum-docs: karyos/design/trace-clocks.md, "Time evidence
//! entries"; quantstratum/karyos#1065).
//!
//! One entry per segment and clock: the clock, the range it covers, its
//! smallest and largest timestamps, granularity, the combined bound at
//! each end, and the digests of the calibration and UTC reference records
//! used. The entries are the bytes of one segment store (recording 1) in
//! `time-evidence/` of the archive directory, each sealed in that
//! directory's own integrity journal with range kind 1 as it is appended,
//! so `karyos-catalog verify <archive>/time-evidence` verifies them. An
//! entry is appended only after its range's own seal.

use std::path::{Path, PathBuf};

use super::Digest;
use super::journal::{IntegrityError, IntegrityJournal};
use super::time::{Requirement, Source, SyncState, Verdict};
use crate::disk::Disk;
use crate::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

#[cfg(test)]
mod tests;

/// An entry's length in bytes: 25 words.
pub const ENTRY_LENGTH: usize = 200;
/// The entries' subdirectory of the archive directory.
pub const DIR: &str = "time-evidence";
/// The entries' recording id in their store, and their seals' subject.
pub const ENTRIES: u64 = 1;
/// The entry layout's version.
const VERSION: u64 = 1;
/// The bound meaning `no_evidence`.
pub const NO_BOUND: u64 = u64::MAX;

/// One time evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// How the clock is synchronised.
    pub source: Source,
    /// Its state.
    pub sync_state: SyncState,
    /// The calibration `from` identity: driver id low and high, journal,
    /// domain, epoch.
    pub clock: [u64; 5],
    /// The recording, never 0.
    pub recording: u64,
    /// The first position covered.
    pub start: u64,
    /// The end, exclusive.
    pub end: u64,
    /// The smallest timestamp in the range, in the clock's unit.
    pub min_time: u64,
    /// The largest.
    pub max_time: u64,
    /// The granularity, in the clock's unit; 0 not stated.
    pub granularity: u64,
    /// The combined bound at `min_time`, in ns; [`NO_BOUND`] for none.
    pub bound_min_ns: u64,
    /// At `max_time`.
    pub bound_max_ns: u64,
    /// SHA-256 of the calibration record used; zero for none.
    pub calibration: Digest,
    /// SHA-256 of the UTC reference record used; zero for none.
    pub utc_reference: Digest,
    /// The clock's unit in femtoseconds; 0 not stated.
    pub tick_fs: u64,
}

/// Why an entry is refused, in the order of the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EntryError {
    /// Word 0's low byte is not 1.
    #[error("time evidence entry version {0} is not supported")]
    Version(u64),
    /// A reserved bit or word is not zero.
    #[error("a reserved field of a time evidence entry is not zero")]
    Reserved,
    /// An unknown `source` or `sync_state` code.
    #[error("unknown {field} code {value}")]
    Code {
        /// The field.
        field: &'static str,
        /// The value.
        value: u64,
    },
    /// `recording` is 0.
    #[error("a time evidence entry names no recording")]
    Recording,
    /// `start > end`.
    #[error("a time evidence entry's range is reversed")]
    Range,
    /// `min_time > max_time`.
    #[error("a time evidence entry's timestamps are reversed")]
    Times,
    /// A finite bound with no UTC reference record.
    #[error("a bound to UTC without a UTC reference record")]
    Evidence,
}

const ZERO: Digest = [0; 32];

fn words(digest: &Digest) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (word, chunk) in out.iter_mut().zip(digest.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    out
}

fn digest(words: [u64; 4]) -> Digest {
    let mut out = [0u8; 32];
    for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    out
}

impl Entry {
    fn check(&self) -> Result<(), EntryError> {
        if self.recording == 0 {
            return Err(EntryError::Recording);
        }
        if self.start > self.end {
            return Err(EntryError::Range);
        }
        if self.min_time > self.max_time {
            return Err(EntryError::Times);
        }
        if (self.bound_min_ns != NO_BOUND || self.bound_max_ns != NO_BOUND)
            && self.utc_reference == ZERO
        {
            return Err(EntryError::Evidence);
        }
        Ok(())
    }

    /// Encodes the entry.
    ///
    /// # Errors
    ///
    /// The refusals a value can hold: [`EntryError::Recording`],
    /// [`EntryError::Range`], [`EntryError::Times`],
    /// [`EntryError::Evidence`].
    pub fn encode(&self) -> Result<[u8; ENTRY_LENGTH], EntryError> {
        self.check()?;
        let [c0, c1, c2, c3, c4] = self.clock;
        let [a0, a1, a2, a3] = words(&self.calibration);
        let [b0, b1, b2, b3] = words(&self.utc_reference);
        let fields: [u64; 25] = [
            VERSION | ((self.source as u64) << 16) | ((self.sync_state as u64) << 24),
            c0,
            c1,
            c2,
            c3,
            c4,
            self.recording,
            self.start,
            self.end,
            self.min_time,
            self.max_time,
            self.granularity,
            self.bound_min_ns,
            self.bound_max_ns,
            a0,
            a1,
            a2,
            a3,
            b0,
            b1,
            b2,
            b3,
            self.tick_fs,
            0,
            0,
        ];
        let mut out = [0u8; ENTRY_LENGTH];
        for (chunk, field) in out.as_chunks_mut::<8>().0.iter_mut().zip(fields) {
            *chunk = field.to_le_bytes();
        }
        Ok(out)
    }

    /// Decodes and checks an entry.
    ///
    /// # Errors
    ///
    /// The first [`EntryError`], in its declared order.
    pub fn decode(bytes: &[u8; ENTRY_LENGTH]) -> Result<Self, EntryError> {
        let mut fields = [0u64; 25];
        for (field, chunk) in fields.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *field = u64::from_le_bytes(*chunk);
        }
        let [
            w0,
            c0,
            c1,
            c2,
            c3,
            c4,
            recording,
            start,
            end,
            min_time,
            max_time,
            granularity,
            bound_min_ns,
            bound_max_ns,
            a0,
            a1,
            a2,
            a3,
            b0,
            b1,
            b2,
            b3,
            tick_fs,
            r0,
            r1,
        ] = fields;
        if w0 & 0xff != VERSION {
            return Err(EntryError::Version(w0 & 0xff));
        }
        if w0 & 0xffff_ffff_0000_ff00 != 0 || r0 != 0 || r1 != 0 {
            return Err(EntryError::Reserved);
        }
        let code = |field: &'static str, value: u64| EntryError::Code { field, value };
        let source_code = (w0 >> 16) & 0xff;
        let sync_code = (w0 >> 24) & 0xff;
        let source = u8::try_from(source_code)
            .ok()
            .and_then(|value| Source::from_code(value).ok())
            .ok_or(code("source", source_code))?;
        let sync_state = u8::try_from(sync_code)
            .ok()
            .and_then(|value| SyncState::from_code(value).ok())
            .ok_or(code("sync_state", sync_code))?;
        let entry = Self {
            source,
            sync_state,
            clock: [c0, c1, c2, c3, c4],
            recording,
            start,
            end,
            min_time,
            max_time,
            granularity,
            bound_min_ns,
            bound_max_ns,
            calibration: digest([a0, a1, a2, a3]),
            utc_reference: digest([b0, b1, b2, b3]),
            tick_fs,
        };
        entry.check()?;
        Ok(entry)
    }

    /// The entry's verdict against `requirement`, in SPEC.md §8.4's
    /// precedence: `not_met` when unsynchronised; `no_evidence` when any
    /// input is missing (a code or the granularity not stated, the unit
    /// unknown, no UTC reference or calibration, a bound missing);
    /// `not_met` when a bound or the granularity exceeds the requirement;
    /// `met` otherwise. The entry must have verified for `met` to stand:
    /// the caller reports only verified entries' verdicts as such.
    #[must_use]
    pub fn verdict(&self, requirement: &Requirement) -> Verdict {
        if self.sync_state == SyncState::Unsynchronised {
            return Verdict::NotMet;
        }
        let granularity_ns = u128::from(self.granularity)
            .checked_mul(u128::from(self.tick_fs))
            .map(|fs| fs.div_ceil(1_000_000));
        let missing = self.source == Source::NotStated
            || self.sync_state == SyncState::NotStated
            || self.granularity == 0
            || self.tick_fs == 0
            || self.utc_reference == ZERO
            || self.calibration == ZERO
            || self.bound_min_ns == NO_BOUND
            || self.bound_max_ns == NO_BOUND;
        let Some(granularity_ns) = granularity_ns.filter(|_| !missing) else {
            return Verdict::NoEvidence;
        };
        let bound = self.bound_min_ns.max(self.bound_max_ns);
        if bound > requirement.max_divergence_ns
            || granularity_ns > u128::from(requirement.max_granularity_ns)
        {
            return Verdict::NotMet;
        }
        Verdict::Met
    }
}

/// The time evidence entries of an archive directory, for appending.
#[derive(Debug)]
pub struct EntryStore<D: Disk> {
    store: SegmentStore<D>,
    journal: IntegrityJournal<D>,
}

/// The entries' directory under `archive`.
#[must_use]
pub fn entries_dir(archive: &Path) -> PathBuf {
    archive.join(DIR)
}

/// The entries' store geometry: one entry never spans more than a write.
fn geometry() -> Result<Geometry, SegmentError> {
    Geometry::with_default_length(1 << 20)
}

/// Why the entries could not be written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The entry is refused.
    #[error(transparent)]
    Entry(#[from] EntryError),
    /// The entries' store failed.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// Their integrity journal failed.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// The directory could not be made.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An entry of the reserved all zero clock identity ("provenance
    /// unknown") with a finite bound or a record cited: only the sentinel,
    /// both bounds [`NO_BOUND`] and both digests zero, is kept
    /// (quantstratum-docs: karyos/design/trace-clocks.md).
    #[error("an entry of the zero clock identity must carry no bound and cite no record")]
    Sentinel,
}

/// Whether `entry` keeps the zero identity's sentinel rule: an entry of
/// the all zero clock identity has both bounds [`NO_BOUND`] and both
/// digests zero. Any other identity passes.
#[must_use]
pub fn keeps_sentinel(entry: &Entry) -> bool {
    entry.clock != [0; 5]
        || (entry.bound_min_ns == NO_BOUND
            && entry.bound_max_ns == NO_BOUND
            && entry.calibration == [0; 32]
            && entry.utc_reference == [0; 32])
}

impl<D: Disk + Clone> EntryStore<D> {
    /// Opens (or makes) the entries of `archive`, in [`entries_dir`],
    /// which the host made.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn open(disk: D, archive: &Path) -> Result<Self, StoreError> {
        let dir = entries_dir(archive);
        let geometry = geometry()?;
        let store = match SegmentStore::recover(
            disk.clone(),
            &dir,
            ENTRIES,
            geometry,
            SyncPolicy::PerSegment,
        ) {
            Ok(recovered) => recovered.store,
            Err(SegmentError::NotFound { .. }) => SegmentStore::create(
                disk.clone(),
                &dir,
                ENTRIES,
                geometry,
                SyncPolicy::PerSegment,
                0,
            )?,
            Err(error) => return Err(error.into()),
        };
        let journal = IntegrityJournal::open(disk, &dir)?.journal;
        Ok(Self { store, journal })
    }

    /// The entries' integrity journal, which the Archive's signer signs.
    pub(crate) fn journal_mut(&mut self) -> &mut IntegrityJournal<D> {
        &mut self.journal
    }

    /// Appends `entry`, durable, and seals it: its seal is the entry's
    /// evidence. Call it only after the entry's own range was sealed.
    ///
    /// # Errors
    ///
    /// [`StoreError`]; an entry written but not sealed is not evidence.
    pub fn append(&mut self, entry: &Entry) -> Result<u64, StoreError> {
        if !keeps_sentinel(entry) {
            return Err(StoreError::Sentinel);
        }
        let bytes = entry.encode()?;
        let at = self.store.written();
        let _ = self.store.append(at, &bytes)?;
        let _ = self.store.sync()?;
        let _ = self.journal.seal_segment(ENTRIES, at, &bytes, false)?;
        Ok(at)
    }
}

/// Reads every entry of `archive` that its entries' integrity journal
/// seals whole, in order. A missing directory reads as none.
///
/// # Errors
///
/// [`StoreError`]; an entry that does not decode is [`StoreError::Entry`].
pub fn read_sealed<D: Disk + Clone>(disk: D, archive: &Path) -> Result<Vec<Entry>, StoreError> {
    let dir = entries_dir(archive);
    let mut probe = disk.clone();
    let (records, _) = match super::journal::read_records(&mut probe, &dir) {
        Ok(records) => records,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let sealed = records
        .iter()
        .filter(|record| record.subject == ENTRIES && record.kind.is_range())
        .map(|record| record.end)
        .max()
        .unwrap_or(0);
    if sealed == 0 {
        return Ok(Vec::new());
    }
    let geometry = geometry()?;
    let mut store = SegmentStore::open_verified(
        crate::disk::ReadOnly(disk),
        &dir,
        ENTRIES,
        geometry,
        SyncPolicy::None,
    )?;
    let mut entries = Vec::new();
    let mut at = 0u64;
    while at.saturating_add(ENTRY_LENGTH as u64) <= sealed.min(store.written()) {
        let mut bytes = [0u8; ENTRY_LENGTH];
        store.read(at, &mut bytes)?;
        entries.push(Entry::decode(&bytes)?);
        at = at.saturating_add(ENTRY_LENGTH as u64);
    }
    Ok(entries)
}
