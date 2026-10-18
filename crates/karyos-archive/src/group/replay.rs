// SPDX-License-Identifier: Apache-2.0

//! Replay of a recording group (`quantstratum-docs: karyos/SPEC.md` §8.3;
//! ADR-0024; archive-gap-analysis.md, phase 3 batch A8;
//! recording-group-replay.md).
//!
//! The journal side, here:
//!
//! - [`check_header`]: a journal replays only under this build's capture
//!   contract and a clock replay knows, and only for the replaying
//!   caller's manifest, compared byte for byte unless it accepts another
//!   (`recording-group-replay.md` section 8).
//! - [`ReplayCursor`]: the events of a recovered journal's complete
//!   prefix, in order, each with its observations and its end, from a
//!   buffer sized when the cursor is opened. Each event says whether a
//!   reference unavailable (template 22) names it, before it is presented
//!   (section 7). Where the prefix ends, the cursor says why with a typed
//!   [`Stop`].
//! - [`CaptureJournal`]: the journal a replay writes what it observes to,
//!   under the replaying caller's manifest (section 9).
//!
//! The Gateway side: [`gateway::ReplayGateway`], the replay implementation
//! of [`super::gateway::GroupGateway`], presents the events through
//! [`effects::ReplayEffects`], which checks each call against its recorded
//! observation; [`mod@reference`] reads a payload by reference from its
//! recording.

use std::path::Path;

use super::journal::{GroupJournal, JournalConfig, JournalError};
use super::prefix::Recovery;
use karyos_codec::CodecError;

use super::record::{
    CONTRACT_VERSION, Clock, EndOutcome, GapMarker, GroupRecord, JournalHeader, MAX_RECORD, Role,
};
use crate::disk::Disk;

#[cfg(test)]
mod tests;

pub mod effects;
pub mod gateway;
pub mod reference;

/// The clock replay presents the readings of.
const CLOCK: Clock = Clock::HostMonotonic;

/// The replaying caller's side of the header check. The contract and the
/// clock are this build's, never the caller's: another contract is not
/// comparable, with no override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayConfig<'a> {
    /// The caller's identity of what replays: the recorded manifest must
    /// be the same bytes, unless `accept_manifest`.
    pub manifest: &'a [u8],
    /// Accept a recorded manifest that differs, as a strategy or version
    /// comparison does on purpose.
    pub accept_manifest: bool,
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

/// Checks a journal's `header`: this build's contract, a clock replay
/// knows, then `config`'s manifest, byte for byte unless it accepts
/// another.
///
/// # Errors
///
/// The first [`HeaderMismatch`] found.
pub fn check_header(
    header: &JournalHeader<'_>,
    config: &ReplayConfig<'_>,
) -> Result<(), HeaderMismatch> {
    if header.contract_version != CONTRACT_VERSION {
        return Err(HeaderMismatch::Contract {
            found: header.contract_version,
            expected: CONTRACT_VERSION,
        });
    }
    if header.clock != CLOCK {
        return Err(HeaderMismatch::Clock {
            found: header.clock,
            expected: CLOCK,
        });
    }
    if !config.accept_manifest && header.manifest != config.manifest {
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
    /// A cursor configuration with fewer than two records per event, or
    /// a buffer (or the list of the events a reference unavailable names)
    /// that cannot be allocated or counted.
    #[error("invalid cursor configuration")]
    InvalidConfig,
    /// The recovery stopped feeding the journal (`Recovery::full`): its
    /// prefixes cover only the journal's start, so replay would claim
    /// less than the journal holds.
    #[error("the recovery's feed stopped")]
    Truncated,
    /// The complete prefix ends inside an event, at `position`: the
    /// recovery and the journal disagree.
    #[error("the complete prefix ends inside an event at {position}")]
    Torn {
        /// Where the event's records stop.
        position: u64,
    },
    /// An event that starts at `position` with a record that is no
    /// event's first.
    #[error("no event starts at {position}")]
    NotAnEvent {
        /// Where.
        position: u64,
    },
    /// The record at `position` encodes again to another length than it
    /// has in the journal.
    #[error("the record at {position} encodes to {found} bytes, not {expected}")]
    Reencoded {
        /// Where.
        position: u64,
        /// Its length in the journal.
        expected: usize,
        /// Its length encoded again.
        found: usize,
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
    /// The complete prefix ends with nothing recorded against it: what
    /// follows, if anything, is not complete yet.
    EndOfPrefix {
        /// The prefix's last event, `first_group_seq - 1` before any.
        complete_recording_seq: u64,
    },
}

/// What [`ReplayCursor::step`] gives: once it gives a stop, it gives the
/// same stop on every later call.
#[derive(Debug)]
pub enum Step<'c> {
    /// The next event of the complete prefix.
    Event(ReplayEvent<'c>),
    /// No event.
    Stop(Stop),
}

/// What a read gave, before it is lent.
#[derive(Debug, Clone, Copy)]
enum Next {
    Event { group_seq: u64, incomplete: bool },
    Stop(Stop),
}

/// One event's records: its first record, its observations in order, and
/// its end, borrowed from the cursor's buffer.
#[derive(Debug, Clone, Copy)]
pub struct ReplayEvent<'c> {
    group_seq: u64,
    reference_unavailable: bool,
    incomplete: bool,
    bytes: &'c [u8],
    spans: &'c [(usize, usize)],
}

impl<'c> ReplayEvent<'c> {
    /// The event's `group_seq`.
    #[must_use]
    pub const fn group_seq(&self) -> u64 {
        self.group_seq
    }

    /// Whether a reference unavailable (template 22) names the event: its
    /// payload by reference will never be there, so replay cannot present
    /// it whole (`recording-group-replay.md` section 7). The record may
    /// lie anywhere after the event; the cursor found it when it opened.
    #[must_use]
    pub const fn reference_unavailable(&self) -> bool {
        self.reference_unavailable
    }

    /// Whether the event's capture is incomplete: its records are those
    /// captured, and its end says incomplete. Replay presents it with its
    /// recorded observations, and stops after it (section 7); the cursor
    /// gives [`Stop::Incomplete`] next.
    #[must_use]
    pub const fn incomplete(&self) -> bool {
        self.incomplete
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

    /// Record `index`'s encoded bytes.
    #[must_use]
    pub fn record_bytes(&self, index: usize) -> Option<&'c [u8]> {
        let &(start, end) = self.spans.get(index)?;
        self.bytes.get(start..end)
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

/// One allocation of `capacity` elements, or [`ReplayError::InvalidConfig`].
pub(crate) fn allocate<T>(capacity: usize) -> Result<Vec<T>, ReplayError> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(capacity)
        .map_err(|_| ReplayError::InvalidConfig)?;
    Ok(vec)
}

/// The events of a recovered journal's complete prefix, in order.
///
/// It allocates only when opened: the buffer, and the events a reference
/// unavailable names. Each [`ReplayCursor::step`] reads one
/// event's records into the buffer and lends them until the next call.
#[derive(Debug)]
pub struct ReplayCursor<D: Disk> {
    journal: GroupJournal<D>,
    /// The next record to read.
    position: u64,
    /// The journal position after the complete prefix's last record.
    complete_end: u64,
    complete_seq: u64,
    /// The `group_seq`s of the prefix that a reference unavailable names,
    /// sorted.
    unavailable: Vec<u64>,
    buffer: Vec<u8>,
    spans: Vec<(usize, usize)>,
    /// The final stop, once reached.
    stopped: Option<Stop>,
    /// The incomplete event the prefix stopped at, while the cursor gives
    /// its records.
    incomplete: Option<u64>,
}

impl<D: Disk> ReplayCursor<D> {
    /// Opens a cursor over `journal`, whose prefixes `recovery` computed
    /// (by [`super::prefix::recover`] on the same journal), after checking
    /// its header against `config`. It reads the journal once to find the
    /// events of the prefix a reference unavailable names.
    ///
    /// # Errors
    ///
    /// [`ReplayError::NoHeader`], [`ReplayError::Header`],
    /// [`ReplayError::InvalidConfig`], [`ReplayError::Truncated`], and the
    /// journal's errors.
    pub fn open(
        mut journal: GroupJournal<D>,
        recovery: &Recovery,
        config: &ReplayConfig<'_>,
        room: CursorConfig,
    ) -> Result<Self, ReplayError> {
        if recovery.full {
            return Err(ReplayError::Truncated);
        }
        if room.records < 2 {
            return Err(ReplayError::InvalidConfig);
        }
        let mut checked = None;
        let mut header_end = 0;
        let _ = journal.walk(0, |_, end, record| {
            if let GroupRecord::Header(header) = record {
                checked = Some(check_header(header, config));
                header_end = end;
            }
            false
        })?;
        checked.ok_or(ReplayError::NoHeader)??;
        let complete_seq = recovery.tracker.complete_recording_seq();
        // Counted first, so the list is one allocation that fails typed.
        // The prefix's events, and the incomplete event the cursor may
        // give after them.
        let last = complete_seq.checked_add(1).unwrap_or(complete_seq);
        let names = |record: &GroupRecord<'_>| match record {
            GroupRecord::Unavailable(record) if record.group_seq <= last => Some(record.group_seq),
            _ => None,
        };
        let mut count = Some(0usize);
        let _ = journal.walk(header_end, |_, _, record| {
            if names(record).is_some() {
                count = count.and_then(|count| count.checked_add(1));
            }
            count.is_some()
        })?;
        let mut unavailable = allocate::<u64>(count.ok_or(ReplayError::InvalidConfig)?)?;
        let _ = journal.walk(header_end, |_, _, record| {
            if let Some(seq) = names(record)
                && unavailable.len() < unavailable.capacity()
            {
                unavailable.push(seq);
            }
            true
        })?;
        unavailable.sort_unstable();
        unavailable.dedup();
        let mut buffer = allocate(room.bytes)?;
        buffer.resize(room.bytes, 0u8);
        Ok(Self {
            journal,
            position: header_end,
            complete_end: recovery.tracker.complete_end().max(header_end),
            complete_seq,
            unavailable,
            buffer,
            spans: allocate(room.records)?,
            stopped: None,
            incomplete: None,
        })
    }

    /// The next event of the complete prefix, or why there is none. A
    /// reference unavailable record is not an event, and is skipped: its
    /// event says it was named. An incomplete event the prefix stopped at
    /// is given once, marked [`ReplayEvent::incomplete`], before
    /// [`Stop::Incomplete`].
    ///
    /// # Errors
    ///
    /// [`ReplayError::Bytes`] and [`ReplayError::Records`] for an event
    /// larger than the buffer, which is not consumed;
    /// [`ReplayError::Torn`], [`ReplayError::NotAnEvent`],
    /// [`ReplayError::Reencoded`]; and the journal's errors.
    pub fn step(&mut self) -> Result<Step<'_>, ReplayError> {
        let next = self.read_next()?;
        Ok(self.view(next))
    }

    /// [`ReplayCursor::step`], past the events before `from`: the first
    /// event at or after it, or the stop.
    ///
    /// # Errors
    ///
    /// As [`ReplayCursor::step`].
    pub fn step_from(&mut self, from: u64) -> Result<Step<'_>, ReplayError> {
        loop {
            let next = self.read_next()?;
            if !matches!(next, Next::Event { group_seq, .. } if group_seq < from) {
                return Ok(self.view(next));
            }
        }
    }

    /// What [`Self::read_next`] read, lent from the buffer.
    fn view(&self, next: Next) -> Step<'_> {
        match next {
            Next::Stop(stop) => Step::Stop(stop),
            Next::Event {
                group_seq,
                incomplete,
            } => Step::Event(ReplayEvent {
                group_seq,
                incomplete,
                reference_unavailable: self.unavailable.binary_search(&group_seq).is_ok(),
                bytes: &self.buffer,
                spans: &self.spans,
            }),
        }
    }

    /// Reads the next event's records into the buffer, or the stop.
    fn read_next(&mut self) -> Result<Next, ReplayError> {
        if let Some(stop) = self.stopped {
            return Ok(Next::Stop(stop));
        }
        loop {
            if self.position >= self.complete_end {
                match self.past_prefix()? {
                    Some(stop) => return Ok(Next::Stop(stop)),
                    // The incomplete event: read it, up to its end.
                    None => continue,
                }
            }
            self.spans.clear();
            let (buffer, spans) = (&mut self.buffer, &mut self.spans);
            let mut fill = 0usize;
            let mut first = None;
            let mut done = None;
            let mut failed = None;
            let _ = self.journal.walk(self.position, |position, end, record| {
                if spans.is_empty() {
                    match record.role() {
                        Role::Unavailable(_) => {
                            done = Some((end, false));
                            return false;
                        }
                        Role::Event(seq) | Role::Uncaptured(seq) => first = Some(seq),
                        _ => {
                            failed = Some(ReplayError::NotAnEvent { position });
                            return false;
                        }
                    }
                }
                let Some(length) = end
                    .checked_sub(position)
                    .and_then(|length| usize::try_from(length).ok())
                else {
                    failed = Some(ReplayError::Torn { position });
                    return false;
                };
                let Some((to, slot)) = fill
                    .checked_add(length)
                    .and_then(|to| buffer.get_mut(fill..to).map(|slot| (to, slot)))
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
                match record.encode(slot) {
                    Ok(found) if found == length => {}
                    Ok(found) => {
                        failed = Some(ReplayError::Reencoded {
                            position,
                            expected: length,
                            found,
                        });
                        return false;
                    }
                    Err(error) => {
                        failed = Some(ReplayError::Record(error));
                        return false;
                    }
                }
                spans.push((fill, to));
                fill = to;
                if matches!(record, GroupRecord::End(_)) {
                    done = Some((end, true));
                    return false;
                }
                true
            })?;
            if let Some(error) = failed {
                self.spans.clear();
                return Err(error);
            }
            match (done, first) {
                // A reference unavailable record: skipped.
                (Some((end, false)), _) => self.position = end,
                (Some((end, true)), Some(group_seq)) if end <= self.complete_end => {
                    self.position = end;
                    let incomplete = self.incomplete == Some(group_seq);
                    if incomplete {
                        self.stopped = Some(Stop::Incomplete { group_seq });
                    }
                    return Ok(Next::Event {
                        group_seq,
                        incomplete,
                    });
                }
                _ => {
                    return Err(ReplayError::Torn {
                        position: self.position,
                    });
                }
            }
        }
    }

    /// The stop at the end of the complete prefix, from the records after
    /// it: the gap the prefix stopped at, if one comes before the next
    /// complete event. At an incomplete event it gives `None`, having set
    /// the cursor to give that event's records next. Reference unavailable
    /// records are skipped: the cursor found those of the prefix when it
    /// opened.
    fn past_prefix(&mut self) -> Result<Option<Stop>, ReplayError> {
        if self.incomplete.is_some() {
            // The incomplete event's records ended before its end record.
            return Err(ReplayError::Torn {
                position: self.position,
            });
        }
        let mut stop = None;
        let mut incomplete = None;
        let _ = self.journal.walk(self.position, |_, end, record| {
            match record {
                GroupRecord::Gap(gap) => {
                    stop = Some(Stop::Gap(*gap));
                    return false;
                }
                GroupRecord::End(record) if record.outcome == EndOutcome::Incomplete => {
                    incomplete = Some((record.group_seq, end));
                    return false;
                }
                // The first event past the prefix is complete and waits on
                // its payload, or on durability.
                GroupRecord::End(_) => return false,
                _ => {}
            }
            true
        })?;
        if let Some((group_seq, end)) = incomplete {
            self.incomplete = Some(group_seq);
            self.complete_end = end;
            return Ok(None);
        }
        let stop = stop.unwrap_or(Stop::EndOfPrefix {
            complete_recording_seq: self.complete_seq,
        });
        self.stopped = Some(stop);
        Ok(Some(stop))
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
    /// Creates the capture journal of the recorded `header`'s group in
    /// `dir`, with the replaying caller's `manifest` in its header
    /// (`recording-group-replay.md` section 9). `dir` is the capture's own
    /// directory: the original's holds the group's journal already, and
    /// is refused ([`crate::segment::SegmentError::Exists`]).
    ///
    /// # Errors
    ///
    /// [`GroupJournal::create`]'s.
    pub fn create(
        disk: D,
        dir: &Path,
        header: &JournalHeader<'_>,
        manifest: &[u8],
        config: JournalConfig,
    ) -> Result<Self, JournalError> {
        let header = JournalHeader {
            manifest,
            ..*header
        };
        Ok(Self {
            journal: GroupJournal::create(disk, dir, &header, config)?,
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
