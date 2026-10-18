// SPDX-License-Identifier: Apache-2.0

//! A recording group's journal on disk (`quantstratum-docs:
//! karyos/design/archive-gap-analysis.md`, phase 3 batch A7b; SPEC §8.3,
//! ADR-0024).
//!
//! - **Store.** The journal is a byte log in a [`SegmentStore`] named by
//!   the group's id, in a directory that holds group journals only (the
//!   segment files are named by id, as a recording's are). Each segment is
//!   one term, so it is a plain run of bytes. The store keeps the written
//!   and durable positions, the sync policies, the CRC-32C of every write
//!   and the recovery of torn writes (A2).
//! - **Records.** Each record is one message of schema 3
//!   ([`super::record`]), back to back. Every record appended is decoded
//!   and checked against the order rules ([`OrderCheck`]) before anything
//!   is written, so the journal on disk is always a valid prefix.
//! - **No record spans two writes.** A record that does not fit what is
//!   left of its segment is preceded by padding to the segment's end: a
//!   fill entry (zeros, nothing written past its first 32 bytes) when 32
//!   bytes or more are left, else zero bytes. A record's envelope never
//!   reads as zeros (its length is never 0), so a reader that finds a zero
//!   length, or fewer bytes than an envelope before the segment's end,
//!   skips to the next segment. Each store write then covers whole records,
//!   so the store's recovery, which cuts at a write boundary, always cuts
//!   between records.
//! - **Recovery.** [`GroupJournal::recover`] recovers the store, then
//!   reads every record kept, checking each and the order rules again: a
//!   record that is not valid there is corruption the CRCs did not catch,
//!   a typed error. The journal may end inside an event: which events are
//!   complete is the prefix tracker's decision (A7c), not the store's.
//!
//! The scratch buffer and the padding are allocated when the journal is
//! created or recovered; appends and reads allocate nothing.

use std::path::Path;

use karyos_codec::{CodecError, ENVELOPE_LENGTH, Envelope};

use super::order::{OrderCheck, OrderError};
use super::record::{GroupRecord, JournalHeader, MAX_RECORD};
use crate::disk::Disk;
use crate::segment::{FILL_RECORD, Geometry, SegmentError, SegmentStore, SyncPolicy};

#[cfg(test)]
mod tests;

/// The default segment length: 16 MiB.
pub const DEFAULT_SEGMENT_LENGTH: u32 = 16 << 20;
/// The shortest segment: the power of two above the largest record
/// ([`MAX_RECORD`], about 64 KiB), so a segment always holds one whole.
pub const MIN_SEGMENT_LENGTH: u32 = 128 << 10;

/// How a journal is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalConfig {
    /// Each segment's length: [`MIN_SEGMENT_LENGTH`] or more.
    pub segment_length: u32,
    /// When the store syncs.
    pub policy: SyncPolicy,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            segment_length: DEFAULT_SEGMENT_LENGTH,
            policy: SyncPolicy::PerSegment,
        }
    }
}

impl JournalConfig {
    fn geometry(self) -> Result<Geometry, JournalError> {
        if self.segment_length < MIN_SEGMENT_LENGTH {
            return Err(JournalError::InvalidConfig);
        }
        Geometry::new(self.segment_length, u64::from(self.segment_length))
            .map_err(|_| JournalError::InvalidConfig)
    }
}

/// A journal's errors.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The configuration is invalid.
    #[error("invalid journal configuration")]
    InvalidConfig,
    /// A record that does not decode: refused, nothing written.
    #[error("invalid record: {0}")]
    Record(#[from] CodecError),
    /// A record that breaks an order rule: refused, nothing written.
    #[error(transparent)]
    Order(#[from] OrderError),
    /// The bytes appended are not whole records.
    #[error("not whole records: {length} bytes left over")]
    NotWhole {
        /// The bytes after the last whole record.
        length: usize,
    },
    /// A header naming another group than the journal's: refused,
    /// nothing written.
    #[error("a header of group {found}, not this journal's")]
    Group {
        /// The group the header named.
        found: u64,
    },
    /// A journal whose header names a capture contract or a clock this
    /// build cannot take: not a corrupt journal, another one.
    #[error("a journal header this build cannot take: {0:?}")]
    Unsupported(super::record::UnsupportedHeader),
    /// A recovered journal holds a record that is not valid at
    /// `position`, or a header naming another group.
    #[error("corrupt journal at {position}")]
    Corrupt {
        /// Where.
        position: u64,
    },
    /// The store's errors.
    #[error(transparent)]
    Segment(#[from] SegmentError),
}

/// A recovered journal.
#[derive(Debug)]
pub struct RecoveredJournal<D: Disk> {
    /// The journal, open for appends after its last record.
    pub journal: GroupJournal<D>,
    /// Where the store's recovery cut the journal, if it did.
    pub cut: Option<crate::segment::Cut>,
}

/// One group's journal.
#[derive(Debug)]
pub struct GroupJournal<D: Disk> {
    store: SegmentStore<D>,
    group_id: u64,
    check: OrderCheck,
    segment_length: u64,
    /// One record, for reads.
    scratch: Vec<u8>,
    /// Zeros, for padding shorter than a fill.
    zeros: [u8; FILL_RECORD],
}

impl<D: Disk> GroupJournal<D> {
    /// Creates the journal of `header`'s group in `dir`, and writes the
    /// header. Its first segment is durable on return; the header is as
    /// durable as the policy makes it.
    ///
    /// # Errors
    ///
    /// [`JournalError::InvalidConfig`], [`JournalError::Record`] for a
    /// header that does not encode, and the store's errors
    /// ([`SegmentError::Exists`] when the group has a journal in `dir`).
    pub fn create(
        disk: D,
        dir: &Path,
        header: &JournalHeader<'_>,
        config: JournalConfig,
    ) -> Result<Self, JournalError> {
        let geometry = config.geometry()?;
        let mut encoded = vec![0u8; MAX_HEADER];
        let length = header.encode(&mut encoded)?;
        encoded.truncate(length);
        let store = SegmentStore::create(disk, dir, header.group_id, geometry, config.policy, 0)?;
        let mut journal = Self {
            store,
            group_id: header.group_id,
            check: OrderCheck::new(),
            segment_length: geometry.segment_length(),
            scratch: vec![0u8; MAX_RECORD],
            zeros: [0; FILL_RECORD],
        };
        journal.append(&encoded)?;
        Ok(journal)
    }

    /// Recovers group `group_id`'s journal in `dir` after a crash or a
    /// close: the store keeps every whole, checked write, then every record
    /// it kept is read and checked again. A journal whose header was never
    /// written comes back empty ([`OrderCheck::records`] is 0), and takes
    /// its header as its first append.
    ///
    /// # Errors
    ///
    /// [`JournalError::Corrupt`] for a record that is not valid where it
    /// lies, or a journal of another group; [`JournalError::InvalidConfig`];
    /// and the store's errors ([`SegmentError::NotFound`] when no journal
    /// was created).
    pub fn recover(
        disk: D,
        dir: &Path,
        group_id: u64,
        config: JournalConfig,
    ) -> Result<RecoveredJournal<D>, JournalError> {
        let geometry = config.geometry()?;
        let recovered = SegmentStore::recover(disk, dir, group_id, geometry, config.policy)?;
        let mut journal = Self {
            store: recovered.store,
            group_id,
            check: OrderCheck::new(),
            segment_length: geometry.segment_length(),
            scratch: vec![0u8; MAX_RECORD],
            zeros: [0; FILL_RECORD],
        };
        let mut position = journal.store.start();
        while position < journal.store.written() {
            let corrupt = || JournalError::Corrupt { position };
            let (length, next) = match journal.read(position) {
                Ok(Some(read)) => read,
                Ok(None) => return Err(corrupt()),
                Err(JournalError::Segment(error)) => return Err(JournalError::Segment(error)),
                Err(_) => return Err(corrupt()),
            };
            if length > 0 {
                let bytes = journal.scratch.get(..length).ok_or_else(corrupt)?;
                let record = GroupRecord::decode(bytes).map_err(|_| {
                    super::record::unsupported_header(bytes)
                        .map_or_else(corrupt, JournalError::Unsupported)
                })?;
                if let GroupRecord::Header(header) = record
                    && header.group_id != group_id
                {
                    return Err(corrupt());
                }
                let role = record.role();
                journal.check.push(role).map_err(|_| corrupt())?;
            }
            position = next;
        }
        Ok(RecoveredJournal {
            journal,
            cut: recovered.cut,
        })
    }

    /// Appends `records`, whole encoded records back to back, after
    /// checking every one: on a refusal nothing is written. Returns the
    /// written position.
    ///
    /// # Errors
    ///
    /// [`JournalError::Record`], [`JournalError::Order`] and
    /// [`JournalError::NotWhole`], which write nothing; the store's errors,
    /// after which the journal fails until recovered.
    pub fn append(&mut self, records: &[u8]) -> Result<u64, JournalError> {
        // Every record is checked first, on a copy of the order state.
        let mut check = self.check;
        let mut offset = 0usize;
        while offset < records.len() {
            let length = record_length(records, offset)?;
            let end = offset.checked_add(length).ok_or(JournalError::NotWhole {
                length: records.len() - offset,
            })?;
            let record = records.get(offset..end).ok_or(JournalError::NotWhole {
                length: records.len() - offset,
            })?;
            let decoded = GroupRecord::decode(record)?;
            if let GroupRecord::Header(header) = decoded
                && header.group_id != self.group_id
            {
                return Err(JournalError::Group {
                    found: header.group_id,
                });
            }
            check.push(decoded.role())?;
            offset = end;
        }
        // Then written: runs of whole records, padded at each segment end
        // a record would cross.
        let mut offset = 0usize;
        let mut run = 0usize;
        while offset < records.len() {
            let length = record_length(records, offset)?;
            let end = offset.checked_add(length).ok_or(JournalError::NotWhole {
                length: records.len() - offset,
            })?;
            let pending = u64::try_from(end - run).map_err(|_| JournalError::InvalidConfig)?;
            if pending > self.room() {
                self.write_run(records, run, offset)?;
                self.pad()?;
                run = offset;
            }
            offset = end;
        }
        self.write_run(records, run, offset)?;
        self.check = check;
        Ok(self.store.written())
    }

    /// Reads the records from `from`, in order, giving each with its
    /// position and its end to `visit` until it returns `false` or the
    /// written position is reached; padding is skipped. Returns where it
    /// stopped: the position of the record `visit` declined, or the
    /// written position. `from` must be a record boundary: 0, a position
    /// `visit` was given, or a position `walk` returned.
    ///
    /// # Errors
    ///
    /// [`JournalError::Corrupt`] for bytes that are not a record where one
    /// starts, and the store's errors.
    pub fn walk(
        &mut self,
        from: u64,
        mut visit: impl FnMut(u64, u64, &GroupRecord<'_>) -> bool,
    ) -> Result<u64, JournalError> {
        let mut position = from;
        while let Some((length, next)) = self.read(position)? {
            if length > 0 {
                let bytes = self
                    .scratch
                    .get(..length)
                    .ok_or(JournalError::Corrupt { position })?;
                let record = GroupRecord::decode(bytes).map_err(|_| {
                    super::record::unsupported_header(bytes).map_or(
                        JournalError::Corrupt { position },
                        JournalError::Unsupported,
                    )
                })?;
                let end = u64::try_from(length)
                    .ok()
                    .and_then(|length| position.checked_add(length))
                    .ok_or(JournalError::Corrupt { position })?;
                if !visit(position, end, &record) {
                    return Ok(position);
                }
            }
            position = next;
        }
        Ok(position)
    }

    /// Reads the record at `position` into the scratch: `Some((length,
    /// next))`, a length of 0 for padding up to `next`, the next segment;
    /// `None` at the written position.
    fn read(&mut self, position: u64) -> Result<Option<(usize, u64)>, JournalError> {
        let written = self.store.written();
        if position >= written {
            return Ok(None);
        }
        let segment_end = position
            .checked_sub(position % self.segment_length)
            .and_then(|base| base.checked_add(self.segment_length))
            .ok_or(JournalError::Corrupt { position })?;
        let left = segment_end.min(written) - position;
        let envelope = u64::try_from(ENVELOPE_LENGTH).map_err(|_| JournalError::InvalidConfig)?;
        // Padding always runs to its segment's end: a short tail or a zero
        // length before the written position's segment end is no padding
        // the journal wrote.
        let padded = segment_end <= written;
        if left < envelope {
            return if padded {
                Ok(Some((0, segment_end)))
            } else {
                Err(JournalError::Corrupt { position })
            };
        }
        let head = self
            .scratch
            .get_mut(..ENVELOPE_LENGTH)
            .ok_or(JournalError::InvalidConfig)?;
        self.store.read(position, head)?;
        let declared = Envelope::read(head)?.message_length;
        if declared == 0 {
            return if padded {
                Ok(Some((0, segment_end)))
            } else {
                Err(JournalError::Corrupt { position })
            };
        }
        let length = usize::try_from(declared)
            .ok()
            .filter(|length| *length >= ENVELOPE_LENGTH && *length <= MAX_RECORD)
            .ok_or(JournalError::Corrupt { position })?;
        let next = position
            .checked_add(u64::from(declared))
            .filter(|next| *next <= segment_end.min(written))
            .ok_or(JournalError::Corrupt { position })?;
        let rest = self
            .scratch
            .get_mut(ENVELOPE_LENGTH..length)
            .ok_or(JournalError::Corrupt { position })?;
        let at = position
            .checked_add(envelope)
            .ok_or(JournalError::Corrupt { position })?;
        self.store.read(at, rest)?;
        Ok(Some((length, next)))
    }

    /// Bytes left in the written position's segment.
    fn room(&self) -> u64 {
        self.segment_length - self.store.written() % self.segment_length
    }

    /// Writes `records[from..to]` at the written position.
    fn write_run(&mut self, records: &[u8], from: usize, to: usize) -> Result<(), JournalError> {
        if from == to {
            return Ok(());
        }
        let run = records
            .get(from..to)
            .ok_or(JournalError::NotWhole { length: to - from })?;
        self.store.append(self.store.written(), run)?;
        Ok(())
    }

    /// Pads the written position's segment to its end.
    fn pad(&mut self) -> Result<(), JournalError> {
        let room = self.room();
        let written = self.store.written();
        if room >= u64::try_from(FILL_RECORD).map_err(|_| JournalError::InvalidConfig)? {
            let extent = u32::try_from(room).map_err(|_| JournalError::InvalidConfig)?;
            self.store.append_fill(written, &self.zeros, extent)?;
        } else {
            let length = usize::try_from(room).map_err(|_| JournalError::InvalidConfig)?;
            let zeros = self
                .zeros
                .get(..length)
                .ok_or(JournalError::InvalidConfig)?;
            self.store.append(written, zeros)?;
        }
        Ok(())
    }

    /// The group.
    #[must_use]
    pub const fn group_id(&self) -> u64 {
        self.group_id
    }

    /// The journal's order state after its last record.
    #[must_use]
    pub const fn order(&self) -> &OrderCheck {
        &self.check
    }

    /// Its sync policy.
    #[must_use]
    pub const fn policy(&self) -> SyncPolicy {
        self.store.policy()
    }

    /// The end of the last record written.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.store.written()
    }

    /// The end of what a sync made durable.
    #[must_use]
    pub const fn durable(&self) -> u64 {
        self.store.durable()
    }

    /// Makes everything written durable; returns the durable position.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn sync(&mut self) -> Result<u64, JournalError> {
        Ok(self.store.sync()?)
    }

    /// The interval policy's clock ([`SegmentStore::tick`]).
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn tick(&mut self, now_ns: u64) -> Result<u64, JournalError> {
        Ok(self.store.tick(now_ns)?)
    }

    /// Closes the journal with everything written durable; returns the
    /// durable position.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn close(self) -> Result<u64, JournalError> {
        Ok(self.store.close_synced()?)
    }
}

/// The longest header record.
const MAX_HEADER: usize = 12 + 24 + 2 + super::record::MAX_MANIFEST;

/// The length of the record at `offset` of `records`, from its envelope.
fn record_length(records: &[u8], offset: usize) -> Result<usize, JournalError> {
    let rest = records.get(offset..).unwrap_or_default();
    let declared = Envelope::read(rest)
        .map_err(|_| JournalError::NotWhole { length: rest.len() })?
        .message_length;
    let length =
        usize::try_from(declared).map_err(|_| JournalError::NotWhole { length: rest.len() })?;
    if length < ENVELOPE_LENGTH || length > rest.len() || length > MAX_RECORD {
        return Err(JournalError::NotWhole { length: rest.len() });
    }
    Ok(length)
}
