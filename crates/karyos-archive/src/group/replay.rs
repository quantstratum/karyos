// SPDX-License-Identifier: Apache-2.0

//! Replay of a recording group, the first part (`quantstratum-docs:
//! karyos/SPEC.md` §8.3; ADR-0024; archive-gap-analysis.md, phase 3 batch
//! A8).
//!
//! Built here, with no Gateway yet:
//!
//! - [`check_header`]: a journal replays only under the capture contract
//!   and the clock it was captured with, and only for the manifest it
//!   names, compared byte for byte.
//! - [`ReplayCursor`]: the events of a recovered journal's complete
//!   prefix, in order, each with its observations and its end, from a
//!   buffer sized when the cursor is opened. Where the prefix ends, the
//!   cursor says why with a typed [`Stop`].
//! - [`CaptureJournal`]: the journal a replay writes what it observes to,
//!   for the comparison with the recorded one.
//!
//! The checks of each call against its recorded observation wait for the
//! Gateway's operation trait (A7d).

use std::path::Path;

use super::journal::{GroupJournal, JournalConfig, JournalError};
use super::prefix::Recovery;
use karyos_codec::CodecError;

use super::record::{
    Clock, EndOutcome, GapMarker, GroupRecord, JournalHeader, MAX_RECORD, ReferenceUnavailable,
    Role,
};
use crate::disk::Disk;

#[cfg(test)]
mod tests;

/// What a replay expects of the journal it replays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected<'a> {
    /// The capture contract the replay implements.
    pub contract_version: u16,
    /// The clock whose readings the replay presents.
    pub clock: Clock,
    /// The caller's identity of what replays: the recorded manifest must
    /// be the same bytes.
    pub manifest: &'a [u8],
}

/// How a journal's header differs from what the replay expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderMismatch {
    /// Another capture contract.
    #[error("captured under contract {found}, replaying {expected}")]
    Contract {
        /// The journal's.
        found: u16,
        /// The replay's.
        expected: u16,
    },
    /// Another clock.
    #[error("captured with clock {found:?}, replaying {expected:?}")]
    Clock {
        /// The journal's.
        found: Clock,
        /// The replay's.
        expected: Clock,
    },
    /// Another manifest.
    #[error("the manifest differs")]
    Manifest,
}

/// Checks a journal's `header` against what the replay `expected`: the
/// contract, the clock, then the manifest, byte for byte.
///
/// # Errors
///
/// The first [`HeaderMismatch`] found.
pub fn check_header(
    header: &JournalHeader<'_>,
    expected: &Expected<'_>,
) -> Result<(), HeaderMismatch> {
    if header.contract_version != expected.contract_version {
        return Err(HeaderMismatch::Contract {
            found: header.contract_version,
            expected: expected.contract_version,
        });
    }
    if header.clock != expected.clock {
        return Err(HeaderMismatch::Clock {
            found: header.clock,
            expected: expected.clock,
        });
    }
    if header.manifest != expected.manifest {
        return Err(HeaderMismatch::Manifest);
    }
    Ok(())
}

/// A replay's errors.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The journal holds no header.
    #[error("the journal holds no header")]
    NoHeader,
    /// The header is not what the replay expects.
    #[error(transparent)]
    Header(#[from] HeaderMismatch),
    /// An event's records do not fit the buffer's bytes.
    #[error("an event needs more than {capacity} bytes")]
    Bytes {
        /// The buffer's bytes.
        capacity: usize,
    },
    /// An event has more records than the buffer holds.
    #[error("an event has more than {capacity} records")]
    Records {
        /// The buffer's records.
        capacity: usize,
    },
    /// The complete prefix ends inside an event, at `position`: the
    /// recovery and the journal disagree.
    #[error("the complete prefix ends inside an event at {position}")]
    Torn {
        /// Where the event's records stop.
        position: u64,
    },
    /// A record that does not encode again.
    #[error(transparent)]
    Record(#[from] CodecError),
    /// The journal's errors.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Why a cursor gives no event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The prefix ends at a gap marker: the events it names were not
    /// captured.
    Gap(GapMarker),
    /// The prefix ends at an event whose capture is incomplete.
    Incomplete {
        /// Its `group_seq`.
        group_seq: u64,
    },
    /// An event already given, by `group_seq`, has a payload by reference
    /// that its recording will never hold. Not an end: the next call goes
    /// on after it.
    ReferenceUnavailable(ReferenceUnavailable),
    /// The complete prefix ends with nothing recorded against it: what
    /// follows, if anything, is not complete yet.
    EndOfPrefix {
        /// The prefix's last event, `first_group_seq - 1` before any.
        complete_recording_seq: u64,
    },
}

impl Stop {
    /// Whether the cursor gives nothing more.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        !matches!(self, Self::ReferenceUnavailable(_))
    }
}

/// What [`ReplayCursor::step`] gives.
#[derive(Debug)]
pub enum Step<'c> {
    /// The next event of the complete prefix.
    Event(ReplayEvent<'c>),
    /// No event.
    Stop(Stop),
}

/// One event's records: its first record, its observations in order, and
/// its end, borrowed from the cursor's buffer.
#[derive(Debug, Clone, Copy)]
pub struct ReplayEvent<'c> {
    group_seq: u64,
    bytes: &'c [u8],
    spans: &'c [(usize, usize)],
}

impl<'c> ReplayEvent<'c> {
    /// The event's `group_seq`.
    #[must_use]
    pub const fn group_seq(&self) -> u64 {
        self.group_seq
    }

    /// The number of records, its first and its end included.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.spans.len()
    }

    /// Never: an event has at least its first record and its end.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The records' encoded bytes, back to back.
    #[must_use]
    pub fn bytes(&self) -> &'c [u8] {
        let end = self.spans.last().map_or(0, |&(_, end)| end);
        self.bytes.get(..end).unwrap_or_default()
    }

    /// Record `index`, decoded.
    ///
    /// # Errors
    ///
    /// The decoder's: none for a record the journal checked.
    pub fn record(&self, index: usize) -> Option<Result<GroupRecord<'c>, CodecError>> {
        let &(start, end) = self.spans.get(index)?;
        let bytes = self.bytes.get(start..end)?;
        Some(GroupRecord::decode(bytes))
    }

    /// The records, decoded, in order.
    pub fn records(&self) -> impl Iterator<Item = Result<GroupRecord<'c>, CodecError>> + '_ {
        (0..self.spans.len()).filter_map(|index| self.record(index))
    }
}

/// The room a cursor's buffer has for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorConfig {
    /// Bytes for one event's records: at least [`MAX_RECORD`] times
    /// `records` holds any event of that many records.
    pub bytes: usize,
    /// Records in one event, its first and its end included: at least 2.
    pub records: usize,
}

/// The events of a recovered journal's complete prefix, in order.
///
/// It allocates only when opened. Each [`ReplayCursor::step`] reads one
/// event's records into the buffer and lends them until the next call.
#[derive(Debug)]
pub struct ReplayCursor<D: Disk> {
    journal: GroupJournal<D>,
    /// The next record to read.
    position: u64,
    /// The journal position after the complete prefix's last record.
    complete_end: u64,
    complete_seq: u64,
    buffer: Vec<u8>,
    spans: Vec<(usize, usize)>,
    /// The final stop, once reached.
    stopped: Option<Stop>,
}

impl<D: Disk> ReplayCursor<D> {
    /// Opens a cursor over `journal`, whose prefixes `recovery` computed
    /// (by [`super::prefix::recover`] on the same journal), after checking
    /// its header against `expected`.
    ///
    /// # Errors
    ///
    /// [`ReplayError::NoHeader`], [`ReplayError::Header`], and the
    /// journal's errors.
    pub fn open(
        mut journal: GroupJournal<D>,
        recovery: &Recovery,
        expected: &Expected<'_>,
        config: CursorConfig,
    ) -> Result<Self, ReplayError> {
        let mut checked = None;
        let mut header_end = 0;
        let _ = journal.walk(0, |_, end, record| {
            if let GroupRecord::Header(header) = record {
                checked = Some(check_header(header, expected));
                header_end = end;
            }
            false
        })?;
        checked.ok_or(ReplayError::NoHeader)??;
        Ok(Self {
            journal,
            position: header_end,
            complete_end: recovery.tracker.complete_end().max(header_end),
            complete_seq: recovery.tracker.complete_recording_seq(),
            buffer: vec![0u8; config.bytes],
            spans: Vec::with_capacity(config.records.max(2)),
            stopped: None,
        })
    }

    /// The next event of the complete prefix, or why there is none.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Bytes`] and [`ReplayError::Records`] for an event
    /// larger than the buffer, which is not consumed;
    /// [`ReplayError::Torn`]; and the journal's errors.
    pub fn step(&mut self) -> Result<Step<'_>, ReplayError> {
        if let Some(stop) = self.stopped {
            return Ok(Step::Stop(stop));
        }
        if self.position >= self.complete_end {
            return self.past_prefix().map(Step::Stop);
        }
        self.spans.clear();
        let (buffer, spans) = (&mut self.buffer, &mut self.spans);
        let mut fill = 0usize;
        let mut first = None;
        let mut done = None;
        let mut failed = None;
        let _ = self.journal.walk(self.position, |position, end, record| {
            if spans.is_empty()
                && let GroupRecord::Unavailable(unavailable) = record
            {
                done = Some((end, Some(*unavailable)));
                return false;
            }
            let length = usize::try_from(end - position).unwrap_or(usize::MAX);
            let Some(slot) = fill
                .checked_add(length)
                .and_then(|to| buffer.get_mut(fill..to))
            else {
                failed = Some(ReplayError::Bytes {
                    capacity: buffer.len(),
                });
                return false;
            };
            if spans.len() == spans.capacity() {
                failed = Some(ReplayError::Records {
                    capacity: spans.capacity(),
                });
                return false;
            }
            if let Err(error) = record.encode(slot) {
                failed = Some(ReplayError::Record(error));
                return false;
            }
            spans.push((fill, fill + length));
            fill += length;
            if let Role::Event(seq) | Role::Uncaptured(seq) = record.role() {
                first = Some(seq);
            }
            if matches!(record, GroupRecord::End(_)) {
                done = Some((end, None));
                return false;
            }
            true
        })?;
        if let Some(error) = failed {
            self.spans.clear();
            return Err(error);
        }
        match done {
            Some((end, Some(unavailable))) => {
                self.position = end;
                Ok(Step::Stop(Stop::ReferenceUnavailable(unavailable)))
            }
            Some((end, None)) if end <= self.complete_end => {
                self.position = end;
                Ok(Step::Event(ReplayEvent {
                    group_seq: first.unwrap_or_default(),
                    bytes: &self.buffer,
                    spans: &self.spans,
                }))
            }
            _ => Err(ReplayError::Torn {
                position: self.position,
            }),
        }
    }

    /// The stop at the end of the complete prefix, from the records after
    /// it: a reference unavailable for an event in the prefix comes first,
    /// then the gap or the incomplete event the prefix stopped at.
    fn past_prefix(&mut self) -> Result<Stop, ReplayError> {
        let complete_seq = self.complete_seq;
        let mut unavailable = None;
        let mut stop = None;
        let _ = self.journal.walk(self.position, |_, end, record| {
            match record {
                GroupRecord::Unavailable(record) if record.group_seq <= complete_seq => {
                    unavailable = Some((end, *record));
                    return false;
                }
                GroupRecord::Unavailable(_) => {}
                GroupRecord::Gap(gap) => {
                    stop = Some(Stop::Gap(*gap));
                    return false;
                }
                GroupRecord::End(end) if end.outcome == EndOutcome::Incomplete => {
                    stop = Some(Stop::Incomplete {
                        group_seq: end.group_seq,
                    });
                    return false;
                }
                // The first event past the prefix is complete and waits on
                // its payload, or on durability: nothing is recorded
                // against the prefix.
                GroupRecord::End(_) => return false,
                _ => {}
            }
            true
        })?;
        if let Some((end, record)) = unavailable {
            self.position = end;
            return Ok(Stop::ReferenceUnavailable(record));
        }
        let stop = stop.unwrap_or(Stop::EndOfPrefix {
            complete_recording_seq: complete_seq,
        });
        self.stopped = Some(stop);
        Ok(stop)
    }

    /// The journal, given back.
    #[must_use]
    pub fn into_journal(self) -> GroupJournal<D> {
        self.journal
    }
}

/// The journal a replay captures to: one record at a time, each checked
/// by the journal's order rules.
#[derive(Debug)]
pub struct CaptureJournal<D: Disk> {
    journal: GroupJournal<D>,
    /// One encoded record.
    scratch: Vec<u8>,
}

impl<D: Disk> CaptureJournal<D> {
    /// Creates the capture journal of `header`'s group in `dir`. A replay
    /// passes the recorded header, so that the two journals compare.
    ///
    /// # Errors
    ///
    /// [`GroupJournal::create`]'s.
    pub fn create(
        disk: D,
        dir: &Path,
        header: &JournalHeader<'_>,
        config: JournalConfig,
    ) -> Result<Self, JournalError> {
        Ok(Self {
            journal: GroupJournal::create(disk, dir, header, config)?,
            scratch: vec![0u8; MAX_RECORD],
        })
    }

    /// Appends `record`; returns the written position.
    ///
    /// # Errors
    ///
    /// [`JournalError::Record`] for a record that does not encode, and
    /// [`GroupJournal::append`]'s.
    pub fn append(&mut self, record: &GroupRecord<'_>) -> Result<u64, JournalError> {
        let length = record.encode(&mut self.scratch)?;
        let bytes = self
            .scratch
            .get(..length)
            .ok_or(JournalError::NotWhole { length })?;
        self.journal.append(bytes)
    }

    /// The journal.
    #[must_use]
    pub const fn journal(&self) -> &GroupJournal<D> {
        &self.journal
    }

    /// The journal, given back, to sync or close.
    #[must_use]
    pub fn into_journal(self) -> GroupJournal<D> {
        self.journal
    }
}
