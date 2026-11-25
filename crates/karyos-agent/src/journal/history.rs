// SPDX-License-Identifier: Apache-2.0

//! The journal's history and change stream (R-CORE-14; karyos#725): pages
//! of the operations journal's records, read from the journal's own
//! recording with a cursor the reader keeps.
//!
//! - **Identity.** A record is named by its journal recording and its
//!   position in it, which the record keeps for as long as the journal
//!   retains it: across the agent's restarts, clean or not, as the agent
//!   resumes its open recording. A new recording (a journal stopped by
//!   another hand) is a new identity: a cursor of another recording is
//!   refused, typed, with the current one, never read as a position in it.
//! - **Only durable records.** A page ends at the journal's durable end
//!   (`head`), never past it: a record a crash can still cut from the tail
//!   is never served, so no cursor a page gave can point past what a
//!   restart keeps.
//! - **The sequence.** Each record carries its `position` and the `next`
//!   position, the next record's; a page carries `next`, where the
//!   following page starts. Read from a page's `next`, the records follow
//!   one another with no position left out: a reader detects a gap from
//!   the sequence alone, as a record whose `position` is not the previous
//!   one's `next`.
//! - **The retention floor.** Every page states `floor`, the oldest
//!   position the journal still holds. A cursor below it (a purge ran)
//!   is refused `below_floor` with the floor, never answered with an
//!   empty page.
//! - **Explicit gaps.** An unknown interval the journal recorded (an
//!   unclean stop, a torn tail, a request without its outcome, a journal
//!   replaced) is a record of its own kind, `unknown_interval`, with its
//!   reason; a page crossing one serves it in place and lists its
//!   position in `unknown_intervals`. A frame that does not decode as a
//!   record is served as kind `undecodable`, never skipped.
//! - **The handoff.** The view (`view`) states the journal's `head`: the
//!   position of the first record not yet in the journal when the view
//!   was taken. The view and the head are taken on the agent's one
//!   polling thread, which also makes every append, so a reader that
//!   reads the view and then follows the history from its `head` misses
//!   no record written after the view and sees none written before it
//!   twice. The journal is the agent's change stream: every operation and
//!   every change of its journal state (holds, purges, gaps and their
//!   acknowledgements) is a record in it.
//! - **Bounds.** A page holds at most [`HISTORY_MAX`] records, each one
//!   frame read from the journal's segment files, so a read holds the
//!   polling thread, and every guard operation waiting behind it, for one
//!   bounded page.

use karyos_sys::frame::{FRAME_ALIGNMENT, FrameType, HEADER_LENGTH, Word0};

use super::{Journal, JournalRecord, Kind};

#[cfg(test)]
mod tests;

/// The records a page holds when the reader names no count.
pub const HISTORY_DEFAULT: usize = 64;
/// The most records one page holds.
pub const HISTORY_MAX: usize = 256;

/// Where a history read starts: a recording and a position in it, as a
/// page's `next` or the view's `head` gave them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryCursor {
    /// The journal recording.
    pub recording: u64,
    /// The position in it.
    pub position: u64,
}

impl HistoryCursor {
    /// Position `position` of recording `recording`.
    #[must_use]
    pub const fn new(recording: u64, position: u64) -> Self {
        Self {
            recording,
            position,
        }
    }
}

/// One record of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryRecord {
    /// Where its frame starts.
    pub position: u64,
    /// Where the next record's frame starts, past any padding: the next
    /// record's `position`, or the page's `next` for its last record.
    pub next: u64,
    /// The record; `None` for a frame that does not decode as one.
    pub record: Option<JournalRecord>,
}

/// A page of the journal's history.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryPage {
    /// The journal recording the positions belong to.
    pub recording: u64,
    /// The oldest position the journal holds: below it, a purge removed
    /// the records.
    pub floor: u64,
    /// The journal's durable end when the page was read.
    pub head: u64,
    /// The records, oldest first.
    pub records: Vec<HistoryRecord>,
    /// Where the next page starts; `head` once the page reached it.
    pub next: u64,
}

impl HistoryPage {
    /// The positions of the unknown intervals the page crosses.
    #[must_use]
    pub fn unknown_intervals(&self) -> Vec<u64> {
        self.records
            .iter()
            .filter(|record| {
                record
                    .record
                    .as_ref()
                    .is_some_and(|record| record.kind == Kind::UnknownInterval)
            })
            .map(|record| record.position)
            .collect()
    }
}

/// Why a history read was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HistoryRefusal {
    /// The agent keeps no journal (no `--journal`).
    NotConfigured,
    /// The journal cannot be read: it could not be opened, or an append
    /// failed, until the agent restarts.
    Unavailable,
    /// The cursor names another recording than the journal's: the reader
    /// starts again at `floor` of `recording`.
    RecordingChanged {
        /// The journal's recording.
        recording: u64,
        /// Its floor.
        floor: u64,
    },
    /// The cursor is below the retention floor: a purge removed it.
    BelowFloor {
        /// The journal's recording.
        recording: u64,
        /// The oldest position it holds.
        floor: u64,
    },
    /// The cursor is past the journal's durable end.
    Ahead {
        /// The journal's recording.
        recording: u64,
        /// Its durable end.
        head: u64,
    },
    /// The cursor is not where a frame starts.
    NotARecord {
        /// The position asked.
        position: u64,
    },
    /// The journal holds something that is not a frame at `position`.
    Corrupt {
        /// Where.
        position: u64,
    },
}

impl HistoryRefusal {
    /// The refusal's name in an answer.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Unavailable => "journal_unavailable",
            Self::RecordingChanged { .. } => "recording_changed",
            Self::BelowFloor { .. } => "below_floor",
            Self::Ahead { .. } => "ahead",
            Self::NotARecord { .. } => "not_a_record",
            Self::Corrupt { .. } => "corrupt",
        }
    }
}

impl Journal {
    /// The journal's recording and durable end, where a reader that took
    /// the view now follows the history from (the handoff); `None` while
    /// the journal is unavailable.
    #[must_use]
    pub fn head(&self) -> Option<HistoryCursor> {
        let recorder = self.recorder.as_ref()?;
        Some(HistoryCursor::new(
            self.recording,
            recorder.store().durable(),
        ))
    }

    /// Up to `count` records (at most [`HISTORY_MAX`]) of the journal's
    /// history from `from`, or from the floor when `from` is `None`, up to
    /// the journal's durable end (see the module).
    ///
    /// # Errors
    ///
    /// [`HistoryRefusal`]: a journal unavailable, a cursor of another
    /// recording, below the floor, past the durable end or not at a
    /// frame, or a frame that cannot be read.
    pub fn history(
        &mut self,
        from: Option<HistoryCursor>,
        count: usize,
    ) -> Result<HistoryPage, HistoryRefusal> {
        let recording = self.recording;
        let recorder = self.recorder.as_mut().ok_or(HistoryRefusal::Unavailable)?;
        let floor = recorder.store().start();
        let head = recorder.store().durable();
        let mut position = match from {
            None => floor,
            Some(cursor) if cursor.recording != recording => {
                return Err(HistoryRefusal::RecordingChanged { recording, floor });
            }
            Some(cursor) if cursor.position < floor => {
                return Err(HistoryRefusal::BelowFloor { recording, floor });
            }
            Some(cursor) if cursor.position > head => {
                return Err(HistoryRefusal::Ahead { recording, head });
            }
            Some(cursor) if !cursor.position.is_multiple_of(u64::from(FRAME_ALIGNMENT)) => {
                return Err(HistoryRefusal::NotARecord {
                    position: cursor.position,
                });
            }
            Some(cursor) => cursor.position,
        };
        let asked = position;
        let count = count.clamp(1, HISTORY_MAX);
        let mut records: Vec<HistoryRecord> = Vec::new();
        let mut header = [0u8; HEADER_LENGTH as usize];
        let mut payload = Vec::new();
        while position < head {
            let corrupt = if position == asked && from.is_some() {
                HistoryRefusal::NotARecord { position }
            } else {
                HistoryRefusal::Corrupt { position }
            };
            recorder.read(position, &mut header).map_err(|_| corrupt)?;
            let word0 = header
                .get(..8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_le_bytes)
                .and_then(|raw| Word0::unpack(raw).ok())
                .ok_or(corrupt)?;
            let extent = if word0.frame_type_code() == FrameType::Pad.code() {
                header
                    .get(24..32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(i64::from_le_bytes)
                    .and_then(|extent| u64::try_from(extent).ok())
                    .ok_or(corrupt)?
            } else {
                // The page ends before the first record past its count,
                // the padding before it already crossed.
                if records.len() == count {
                    break;
                }
                let length = u32::try_from(word0.frame_length())
                    .ok()
                    .filter(|length| *length >= HEADER_LENGTH)
                    .ok_or(corrupt)?;
                let body = usize::try_from(length.abs_diff(HEADER_LENGTH)).map_err(|_| corrupt)?;
                payload.resize(body, 0);
                let at = position
                    .checked_add(u64::from(HEADER_LENGTH))
                    .ok_or(corrupt)?;
                recorder.read(at, &mut payload).map_err(|_| corrupt)?;
                records.push(HistoryRecord {
                    position,
                    next: 0,
                    record: JournalRecord::decode(&payload),
                });
                u64::from(length)
                    .checked_next_multiple_of(u64::from(FRAME_ALIGNMENT))
                    .ok_or(corrupt)?
            };
            if extent == 0 {
                return Err(corrupt);
            }
            position = position
                .checked_add(extent)
                .filter(|end| *end <= head)
                .ok_or(corrupt)?;
        }
        // Each record's `next` is the following record's position, past
        // any padding; the last one's, the page's.
        let mut after = position;
        for record in records.iter_mut().rev() {
            record.next = after;
            after = record.position;
        }
        Ok(HistoryPage {
            recording,
            floor,
            head,
            records,
            next: position,
        })
    }
}
