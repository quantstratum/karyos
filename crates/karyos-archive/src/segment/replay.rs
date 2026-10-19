// SPDX-License-Identifier: Apache-2.0

//! A recording's range read back for a replay (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A5; SPEC §8.2).
//!
//! [`ReplaySource`] reads a recording's segments without changing them:
//! the frames of `[from, to)` in order, each as the log held them. Data
//! comes as whole frames, a padding or aborted block as its canonical
//! record and extent, and a lost range as a gap. Nothing is skipped
//! silently.
//!
//! - **Range.** `from` must be a frame boundary: the start of an entry, or
//!   a frame start inside a data entry, found by walking its verified
//!   frames. The replay ends at the last whole frame, fill or gap end at or
//!   below `to`.
//! - **Bound.** What the recording holds is fixed at [`ReplaySource::open`]:
//!   its segments, and the last entry of the last of them. `to` is clamped
//!   to that entry's end, so a recording that is still being written is
//!   read up to what it held at open, never further; following it live is
//!   the live merge's work (A6). A segment missing between `from` and that
//!   end is [`ReplayError::MissingSegment`], never the recording's end.
//! - **Immutable entries.** The store only appends: an entry, once in the
//!   index, and the data it covers never change. What open found is what
//!   the replay reads, and a CRC checked once holds for the whole replay.
//! - **Errors.** An error is final: every later poll is
//!   [`ReplayError::Failed`].
//! - **Integrity.** No byte is delivered before its entry's CRC holds. An
//!   entry delivered whole in one read is checked as it is read; any
//!   other (one larger than the buffer, or one the range starts or stops
//!   inside) is first read whole through the buffer, its CRC and its frame
//!   lengths checked, then delivered in frame-bounded pieces.
//! - **Pacing.** [`Rate::Full`] yields as fast as it is polled.
//!   [`Rate::AsRecorded`] and [`Rate::Scaled`] hold each entry that
//!   delivers something until its record time, measured from the first
//!   such entry, has passed on the caller's clock (scaled by parts per
//!   million of the recorded pace). Entries without a record time (0)
//!   refuse paced replay with [`ReplayError::RecordTimeUnknown`]; they
//!   never fall back to full speed.
//! - **Index version.** Only a version 2 index (with record times) is
//!   read; a version 1 index is refused as foreign. A recording an earlier
//!   build left open with a version 1 index is refused the same way when
//!   the agent settles it at start.
//!
//! The buffer is allocated once, at [`ReplaySource::open`]; reading
//! allocates only when it opens the next segment's files.

use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use super::{
    ENTRY, Entry, EntryKind, FILL_RECORD, FILL_RECORD_LEN, Geometry, HEADER, Header, HeaderProblem,
    HeaderRead, SegmentError, bases, data_name, entry_offset, index_name,
};
use crate::crc32c::Crc32c;
use crate::disk::Disk;

#[cfg(test)]
mod tests;

/// Frames are aligned in the log and in the segments.
const FRAME_ALIGNMENT: u64 = karyos_sys::frame::FRAME_ALIGNMENT as u64;

/// The recorded pace, in parts per million.
const PPM_UNIT: u64 = 1_000_000;

/// The pace of a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rate {
    /// As fast as the caller polls.
    Full,
    /// At the cadence the recorder wrote at.
    AsRecorded,
    /// The recorded cadence scaled: parts per million of the recorded pace
    /// (2 000 000 is twice as fast).
    Scaled {
        /// The scale.
        ppm: NonZeroU32,
    },
}

/// A replay's error.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The store's files failed to read, or their header is not this
    /// recording's (a version 1 index is foreign).
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// `from` is not a frame boundary of the recording.
    #[error("{position} is not a frame boundary")]
    NotAFrameBoundary {
        /// The position asked for.
        position: u64,
    },
    /// The range lies outside what the recording held at open.
    #[error("[{from}, {to}) is outside the recording")]
    OutOfRange {
        /// The range's start.
        from: u64,
        /// Its end.
        to: u64,
    },
    /// A segment of the range is missing.
    #[error("the segment at {base} is missing")]
    MissingSegment {
        /// Its base.
        base: u64,
    },
    /// A paced replay met an entry without a record time.
    #[error("the entry at {position} has no record time")]
    RecordTimeUnknown {
        /// The entry's start.
        position: u64,
    },
    /// An entry's record time is before the first paced entry's.
    #[error("the entry at {position} was recorded before the replay's first")]
    RecordTimeBackward {
        /// The entry's start.
        position: u64,
    },
    /// An entry is due later than the caller's clock can say.
    #[error("the entry at {position} is due past the clock's range")]
    PacingOverflow {
        /// The entry's start.
        position: u64,
    },
    /// An entry's data failed its CRC, an index entry its own, or a frame's
    /// length does not hold.
    #[error("the recording is corrupt at {position}")]
    Corrupt {
        /// The entry or frame's start.
        position: u64,
    },
    /// An earlier poll failed: a replay's error is final.
    #[error("the replay failed earlier")]
    Failed,
    /// A frame is longer than the replay's buffer, or the buffer is shorter
    /// than one alignment unit.
    #[error("a frame of {length} bytes does not fit the buffer")]
    BufferTooSmall {
        /// The frame's aligned length.
        length: u64,
    },
}

/// A step, its bytes left in the buffer.
enum Next {
    Frames { position: u64, length: usize },
    Fill { position: u64, extent: u32 },
    Gap { from: u64, to: u64 },
    Wait { until_ns: u64 },
    End { position: u64 },
}

/// What a poll yields.
#[derive(Debug, PartialEq, Eq)]
pub enum Step<'a> {
    /// Whole frames at `position`, as the log held them.
    Frames {
        /// Their start.
        position: u64,
        /// The frames, each padded to the alignment but the last.
        bytes: &'a [u8],
    },
    /// A padding or aborted block: its canonical record, covering `extent`
    /// bytes from `position`.
    Fill {
        /// The block's start.
        position: u64,
        /// The canonical record.
        record: &'a [u8],
        /// The block's logical extent.
        extent: u32,
    },
    /// A range the recording lost.
    Gap {
        /// Its start.
        from: u64,
        /// Its end.
        to: u64,
    },
    /// Nothing is due before `until_ns` on the caller's clock.
    Wait {
        /// When the next step is due.
        until_ns: u64,
    },
    /// The replay reached its end, at `position`.
    End {
        /// Where it ended.
        position: u64,
    },
}

/// One segment's files, open.
#[derive(Debug)]
struct Open<F> {
    base: u64,
    index: F,
    data: F,
    entries: u64,
    next_entry: u64,
}

/// The entry being delivered, and how far.
#[derive(Debug, Clone, Copy)]
struct Current {
    entry: Entry,
    /// The next position of the entry to deliver.
    at: u64,
    /// Whether the entry was read whole and its CRC and frames checked.
    verified: bool,
    /// Where delivery of the entry stops: its end, or once verified the
    /// last frame boundary at or below the replay's end.
    limit: u64,
}

/// A replay's reader of one recording's range.
#[derive(Debug)]
pub struct ReplaySource<D: Disk> {
    disk: D,
    dir: PathBuf,
    recording: u64,
    geometry: Geometry,
    position: u64,
    to: u64,
    rate: Rate,
    buffer: Vec<u8>,
    open: Option<Open<D::File>>,
    current: Option<Current>,
    /// The first paced entry's record time and the caller's clock then.
    origin: Option<(u64, u64)>,
    ended: bool,
    /// An earlier poll failed.
    failed: bool,
    /// The state before the last step, for [`ReplaySource::hold`].
    before: Option<Snapshot>,
}

/// Where a replay was before a step.
#[derive(Debug, Clone, Copy)]
struct Snapshot {
    position: u64,
    current: Option<Current>,
    ended: bool,
    base: Option<u64>,
    next_entry: u64,
}

impl<D: Disk> ReplaySource<D> {
    /// Opens recording `recording` in `dir` for the range `[from, to)`,
    /// reading through a buffer of `buffer` bytes (at least the largest
    /// frame). `to` is clamped to the end of what the recording holds now.
    ///
    /// # Errors
    ///
    /// [`ReplayError::OutOfRange`] for an empty or reversed range or one
    /// outside the recording, [`ReplayError::NotAFrameBoundary`],
    /// [`ReplayError::MissingSegment`], [`ReplayError::Corrupt`] for the
    /// entry `from` is inside, [`ReplayError::BufferTooSmall`], and the
    /// store's errors.
    #[allow(
        clippy::too_many_arguments,
        reason = "one recording's range and how to read it"
    )]
    pub fn open(
        disk: D,
        dir: &Path,
        recording: u64,
        geometry: Geometry,
        from: u64,
        to: u64,
        rate: Rate,
        buffer: usize,
    ) -> Result<Self, ReplayError> {
        if from >= to {
            return Err(ReplayError::OutOfRange { from, to });
        }
        if u64::try_from(buffer).map_or(true, |buffer| buffer < FRAME_ALIGNMENT) {
            return Err(ReplayError::BufferTooSmall {
                length: FRAME_ALIGNMENT,
            });
        }
        let mut source = Self {
            disk,
            dir: dir.to_path_buf(),
            recording,
            geometry,
            position: from,
            to,
            rate,
            buffer: vec![0; buffer],
            open: None,
            current: None,
            origin: None,
            ended: false,
            failed: false,
            before: None,
        };
        let held = source.held(from, to)?;
        source.to = to.min(held);
        if from >= source.to {
            return Err(ReplayError::OutOfRange { from, to });
        }
        source.seek(from)?;
        Ok(source)
    }

    /// The next position to deliver.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Where what the recording holds now ends: its last entry's end. The
    /// segments from `from`'s on must follow each other.
    fn held(&mut self, from: u64, to: u64) -> Result<u64, ReplayError> {
        let names = self
            .disk
            .list(&self.dir)
            .map_err(|error| ReplayError::Segment(error.into()))?;
        let first = self.geometry.base_of(from);
        let present: Vec<u64> = bases(self.recording, &names)
            .into_iter()
            .filter(|base| *base >= first)
            .collect();
        if present.first() != Some(&first) {
            return Err(ReplayError::OutOfRange { from, to });
        }
        let mut expected = first;
        for &base in &present {
            if base != expected {
                return Err(ReplayError::MissingSegment { base: expected });
            }
            expected = base
                .checked_add(self.geometry.segment_length)
                .ok_or(SegmentError::PositionOverflow)?;
        }
        for &base in present.iter().rev() {
            let (index, _) = self.open_files(base)?;
            let entries = self.entry_count(&index)?;
            let Some(last) = entries.checked_sub(1) else {
                continue;
            };
            let entry = self.read_entry(&index, last)?;
            return Ok(entry.end().ok_or(SegmentError::PositionOverflow)?);
        }
        Err(ReplayError::OutOfRange { from, to })
    }

    /// Opens a segment's index and data files, read only, and checks the
    /// index's header is this recording's.
    fn open_files(&mut self, base: u64) -> Result<(D::File, D::File), ReplayError> {
        let missing = |error: io::Error| {
            if error.kind() == io::ErrorKind::NotFound {
                ReplayError::MissingSegment { base }
            } else {
                ReplayError::Segment(error.into())
            }
        };
        let index_path = self.dir.join(index_name(self.recording, base));
        let data_path = self.dir.join(data_name(self.recording, base));
        let index = self.disk.open_read(&index_path).map_err(missing)?;
        let data = self.disk.open_read(&data_path).map_err(missing)?;
        let mut bytes = [0u8; HEADER as usize];
        self.disk
            .read_at(&index, 0, &mut bytes)
            .map_err(SegmentError::from)?;
        let bad = |problem| SegmentError::BadHeader { base, problem };
        let header = match Header::read(Some(&bytes)) {
            HeaderRead::Valid(header) => header,
            HeaderRead::Foreign => return Err(bad(HeaderProblem::Foreign).into()),
            HeaderRead::Missing | HeaderRead::Torn => {
                return Err(bad(HeaderProblem::Corrupt).into());
            }
        };
        if (
            header.recording,
            header.base,
            header.segment_length,
            header.term_length,
        ) != (
            self.recording,
            base,
            self.geometry.segment_length,
            self.geometry.term_length,
        ) {
            return Err(bad(HeaderProblem::Mismatch).into());
        }
        Ok((index, data))
    }

    /// The whole entries an index holds now.
    fn entry_count(&mut self, index: &D::File) -> Result<u64, ReplayError> {
        let length = self.disk.len(index).map_err(SegmentError::from)?;
        Ok(length
            .checked_sub(HEADER)
            .map_or(0, |entries| entries / ENTRY))
    }

    /// Entry `number` of an index.
    fn read_entry(&mut self, index: &D::File, number: u64) -> Result<Entry, ReplayError> {
        let at = entry_offset(number).ok_or(SegmentError::PositionOverflow)?;
        let mut bytes = [0u8; ENTRY as usize];
        self.disk
            .read_at(index, at, &mut bytes)
            .map_err(SegmentError::from)?;
        match Entry::decode(&bytes) {
            Some(Ok(entry)) => Ok(entry),
            Some(Err((position, kind))) => {
                Err(SegmentError::UnknownEntryKind { position, kind }.into())
            }
            None => Err(ReplayError::Corrupt { position: at }),
        }
    }

    /// Opens the segment at `base`. Entries written after open lie past
    /// the replay's end, which is clamped to what the recording held then.
    fn open_segment(&mut self, base: u64) -> Result<(), ReplayError> {
        let (index, data) = self.open_files(base)?;
        let entries = self.entry_count(&index)?;
        self.open = Some(Open {
            base,
            index,
            data,
            entries,
            next_entry: 0,
        });
        Ok(())
    }

    /// The next entry of the open segment, opening the next segment past
    /// its last entry.
    fn next_entry(&mut self) -> Result<Option<Entry>, ReplayError> {
        loop {
            let Some(mut open) = self.open.take() else {
                return Ok(None);
            };
            if open.next_entry < open.entries {
                let entry = self.read_entry(&open.index, open.next_entry);
                open.next_entry = open
                    .next_entry
                    .checked_add(1)
                    .ok_or(SegmentError::PositionOverflow)?;
                self.open = Some(open);
                return entry.map(Some);
            }
            let next = open
                .base
                .checked_add(self.geometry.segment_length)
                .ok_or(SegmentError::PositionOverflow)?;
            self.open_segment(next)?;
        }
    }

    /// Positions the reader at `from`, which must be a frame boundary.
    fn seek(&mut self, from: u64) -> Result<(), ReplayError> {
        self.open_segment(self.geometry.base_of(from))?;
        loop {
            let Some(entry) = self.next_entry()? else {
                return Err(ReplayError::OutOfRange { from, to: self.to });
            };
            let end = entry.end().ok_or(SegmentError::PositionOverflow)?;
            if end <= from {
                continue;
            }
            if entry.start > from {
                return Err(ReplayError::OutOfRange { from, to: self.to });
            }
            let mut current = Current {
                entry,
                at: from,
                verified: false,
                limit: end,
            };
            if entry.start < from && entry.kind != EntryKind::Gap {
                if entry.kind == EntryKind::Fill {
                    return Err(ReplayError::NotAFrameBoundary { position: from });
                }
                current.limit = self.verify(entry, Some(from))?;
                current.verified = true;
            }
            self.current = Some(current);
            return Ok(());
        }
    }

    /// Reads data `entry` whole through the buffer: checks its CRC, then
    /// its frames, and that `target`, if any, is one of their starts.
    /// Returns the last frame boundary at or below the replay's end.
    fn verify(&mut self, entry: Entry, target: Option<u64>) -> Result<u64, ReplayError> {
        let open = self.open.as_ref().ok_or(SegmentError::Failed)?;
        let entry_end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        let cap = entry_end.min(self.to);
        let room = u64::try_from(self.buffer.len()).map_err(|_| SegmentError::PositionOverflow)?;
        // Whole alignment units, so a frame's length word is never split.
        let chunk = room
            .checked_div(FRAME_ALIGNMENT)
            .and_then(|units| units.checked_mul(FRAME_ALIGNMENT))
            .ok_or(SegmentError::PositionOverflow)?;
        let mut crc = Crc32c::new();
        let mut at = entry.start;
        let mut frame = entry.start;
        let mut boundary = entry.start;
        let mut hit = target.is_none();
        let mut bad_frame = None;
        while at < entry_end {
            let length = chunk.min(
                entry_end
                    .checked_sub(at)
                    .ok_or(SegmentError::PositionOverflow)?,
            );
            let window = read(
                &mut self.disk,
                &open.data,
                open.base,
                at,
                length,
                &mut self.buffer,
            )?;
            crc.update(window);
            let window_end = at
                .checked_add(length)
                .ok_or(SegmentError::PositionOverflow)?;
            while bad_frame.is_none() && frame < window_end {
                hit |= target == Some(frame);
                match frame_length(window, at, frame, entry_end) {
                    Some(length) => {
                        frame = frame
                            .checked_add(length)
                            .ok_or(SegmentError::PositionOverflow)?;
                        if frame <= cap {
                            boundary = frame;
                        }
                    }
                    None => bad_frame = Some(frame),
                }
            }
            at = window_end;
        }
        if crc.finish() != entry.data_crc {
            return Err(ReplayError::Corrupt {
                position: entry.start,
            });
        }
        if let Some(position) = bad_frame {
            return Err(ReplayError::Corrupt { position });
        }
        match target {
            Some(position) if !hit => Err(ReplayError::NotAFrameBoundary { position }),
            _ => Ok(boundary),
        }
    }

    /// Whether `entry` is due on the caller's clock, else when it is.
    fn pace(&mut self, entry: Entry, now_ns: u64) -> Result<Option<u64>, ReplayError> {
        let ppm = match self.rate {
            Rate::Full => return Ok(None),
            Rate::AsRecorded => PPM_UNIT,
            Rate::Scaled { ppm } => u64::from(ppm.get()),
        };
        let position = entry.start;
        if entry.time_ns == 0 {
            return Err(ReplayError::RecordTimeUnknown { position });
        }
        let (recorded, started) = *self.origin.get_or_insert((entry.time_ns, now_ns));
        let elapsed = entry
            .time_ns
            .checked_sub(recorded)
            .ok_or(ReplayError::RecordTimeBackward { position })?;
        // At most u64::MAX times PPM_UNIT: no u128 overflow.
        let scaled = u128::from(elapsed)
            .checked_mul(u128::from(PPM_UNIT))
            .and_then(|scaled| scaled.checked_div(u128::from(ppm)))
            .and_then(|scaled| u64::try_from(scaled).ok());
        let due = scaled
            .and_then(|scaled| started.checked_add(scaled))
            .ok_or(ReplayError::PacingOverflow { position })?;
        Ok((now_ns < due).then_some(due))
    }

    /// Whether the entry being delivered is paced now: at its first
    /// delivery, or before the replay's first.
    fn paces(&self, current: &Current) -> bool {
        current.at == current.entry.start || self.origin.is_none()
    }

    /// The next step on the caller's clock, `now_ns`.
    ///
    /// # Errors
    ///
    /// [`ReplayError::RecordTimeUnknown`], [`ReplayError::RecordTimeBackward`]
    /// and [`ReplayError::PacingOverflow`] for a paced replay,
    /// [`ReplayError::Corrupt`], [`ReplayError::MissingSegment`],
    /// [`ReplayError::BufferTooSmall`], and the store's errors.
    pub fn poll(&mut self, now_ns: u64) -> Result<Step<'_>, ReplayError> {
        if self.failed {
            return Err(ReplayError::Failed);
        }
        self.before = Some(Snapshot {
            position: self.position,
            current: self.current,
            ended: self.ended,
            base: self.open.as_ref().map(|open| open.base),
            next_entry: self.open.as_ref().map_or(0, |open| open.next_entry),
        });
        let next = match self.next(now_ns) {
            Ok(next) => next,
            Err(error) => {
                // An error is final: the replay's state may be anywhere.
                self.failed = true;
                self.current = None;
                return Err(error);
            }
        };
        Ok(match next {
            Next::Frames { position, length } => Step::Frames {
                position,
                bytes: self.buffer.get(..length).ok_or(SegmentError::Failed)?,
            },
            Next::Fill { position, extent } => Step::Fill {
                position,
                record: self.buffer.get(..FILL_RECORD).ok_or(SegmentError::Failed)?,
                extent,
            },
            Next::Gap { from, to } => Step::Gap { from, to },
            Next::Wait { until_ns } => Step::Wait { until_ns },
            Next::End { position } => Step::End { position },
        })
    }

    /// Takes back the last step, so the next poll yields it again: for a
    /// target that had no room for it. A no-op before the first poll and
    /// after a hold.
    ///
    /// # Errors
    ///
    /// The errors of [`ReplaySource::open`]'s seek, when the step crossed
    /// into the next segment and the replay seeks back; such an error is
    /// final.
    pub fn hold(&mut self) -> Result<(), ReplayError> {
        let Some(before) = self.before.take() else {
            return Ok(());
        };
        if self.failed {
            return Err(ReplayError::Failed);
        }
        self.position = before.position;
        self.current = before.current;
        self.ended = before.ended;
        if let (Some(open), Some(base)) = (self.open.as_mut(), before.base)
            && open.base == base
        {
            open.next_entry = before.next_entry;
            return Ok(());
        }
        // The step crossed into the next segment: seek back.
        self.open = None;
        self.current = None;
        let sought = self.seek(before.position);
        if sought.is_err() {
            self.failed = true;
        }
        sought
    }

    /// The next step, its bytes left in the buffer.
    fn next(&mut self, now_ns: u64) -> Result<Next, ReplayError> {
        if self.ended {
            return Ok(Next::End {
                position: self.position,
            });
        }
        let current = match self.current {
            Some(current) => current,
            None => match self.next_entry()? {
                Some(entry) if entry.start == self.position => Current {
                    entry,
                    at: entry.start,
                    verified: false,
                    limit: entry.end().ok_or(SegmentError::PositionOverflow)?,
                },
                Some(_) => {
                    return Err(ReplayError::Corrupt {
                        position: self.position,
                    });
                }
                None => return Ok(self.end()),
            },
        };
        self.current = Some(current);
        let entry = current.entry;
        let entry_end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        match entry.kind {
            EntryKind::Gap => {
                if self.paces(&current)
                    && let Some(until_ns) = self.pace(entry, now_ns)?
                {
                    return Ok(Next::Wait { until_ns });
                }
                let to = entry_end.min(self.to);
                let from = current.at;
                self.advance(to, entry_end);
                Ok(Next::Gap { from, to })
            }
            EntryKind::Fill => {
                if entry_end > self.to {
                    return Ok(self.end());
                }
                if self.paces(&current)
                    && let Some(until_ns) = self.pace(entry, now_ns)?
                {
                    return Ok(Next::Wait { until_ns });
                }
                self.read_fill(entry)?;
                self.advance(entry_end, entry_end);
                Ok(Next::Fill {
                    position: entry.start,
                    extent: entry.length,
                })
            }
            EntryKind::Data => self.data(current, entry_end, now_ns),
        }
    }

    fn end(&mut self) -> Next {
        self.ended = true;
        self.current = None;
        Next::End {
            position: self.position,
        }
    }

    /// Moves to `to`, dropping the entry once `entry_end` is reached.
    fn advance(&mut self, to: u64, entry_end: u64) {
        self.position = to;
        if to >= entry_end {
            self.current = None;
        } else if let Some(current) = self.current.as_mut() {
            current.at = to;
        }
        if to >= self.to {
            self.ended = true;
        }
    }

    fn read_fill(&mut self, entry: Entry) -> Result<(), ReplayError> {
        let open = self.open.as_ref().ok_or(SegmentError::Failed)?;
        let length = u64::from(FILL_RECORD_LEN);
        let record = read(
            &mut self.disk,
            &open.data,
            open.base,
            entry.start,
            length,
            &mut self.buffer,
        )?;
        if crate::crc32c::crc32c(record) != entry.data_crc {
            return Err(ReplayError::Corrupt {
                position: entry.start,
            });
        }
        Ok(())
    }

    /// The next frames of data `current`, as many whole frames as fit the
    /// buffer and the range. An entry not delivered whole in one read is
    /// verified first.
    fn data(
        &mut self,
        mut current: Current,
        entry_end: u64,
        now_ns: u64,
    ) -> Result<Next, ReplayError> {
        let room = u64::try_from(self.buffer.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let left = entry_end
            .checked_sub(current.at)
            .ok_or(SegmentError::PositionOverflow)?;
        let whole = current.at == current.entry.start && entry_end <= self.to && left <= room;
        if !whole && !current.verified {
            current.limit = self.verify(current.entry, None)?;
            current.verified = true;
            self.current = Some(current);
        }
        if current.limit <= current.at {
            return Ok(self.end());
        }
        if self.paces(&current)
            && let Some(until_ns) = self.pace(current.entry, now_ns)?
        {
            return Ok(Next::Wait { until_ns });
        }
        let open = self.open.as_ref().ok_or(SegmentError::Failed)?;
        let span = current
            .limit
            .checked_sub(current.at)
            .ok_or(SegmentError::PositionOverflow)?
            .min(room);
        let window = read(
            &mut self.disk,
            &open.data,
            open.base,
            current.at,
            span,
            &mut self.buffer,
        )?;
        let window_end = current
            .at
            .checked_add(span)
            .ok_or(SegmentError::PositionOverflow)?;
        if whole && crate::crc32c::crc32c(window) != current.entry.data_crc {
            return Err(ReplayError::Corrupt {
                position: current.entry.start,
            });
        }
        let end = if !whole && window_end == current.limit {
            // The limit is a verified frame boundary.
            window_end
        } else {
            // The whole frames in the window. An entry read whole has its
            // lengths checked here: they must end exactly at its end.
            let (end, first) = whole_frames(window, current.at, entry_end)?;
            if whole && end != window_end {
                return Err(ReplayError::Corrupt { position: end });
            }
            if end == current.at {
                return Err(ReplayError::BufferTooSmall { length: first });
            }
            end
        };
        let position = current.at;
        let length = usize::try_from(
            end.checked_sub(position)
                .ok_or(SegmentError::PositionOverflow)?,
        )
        .map_err(|_| SegmentError::PositionOverflow)?;
        self.advance(end, entry_end);
        Ok(Next::Frames { position, length })
    }
}

/// Reads `length` bytes of a segment's data at `position` into the front
/// of `buffer`.
fn read<'b, D: Disk>(
    disk: &mut D,
    data: &D::File,
    base: u64,
    position: u64,
    length: u64,
    buffer: &'b mut [u8],
) -> Result<&'b [u8], ReplayError> {
    let offset = position
        .checked_sub(base)
        .ok_or(SegmentError::PositionOverflow)?;
    let bytes = usize::try_from(length)
        .ok()
        .and_then(|end| buffer.get_mut(..end))
        .ok_or(ReplayError::BufferTooSmall { length })?;
    disk.read_at(data, offset, bytes)
        .map_err(SegmentError::from)?;
    Ok(bytes)
}

/// The end of the whole frames of `window` (an entry's bytes from
/// `window_start`), and the length of its first frame. A frame whose
/// length word or extent is outside the window does not fit and ends the
/// scan; a length that does not hold is [`ReplayError::Corrupt`].
fn whole_frames(
    window: &[u8],
    window_start: u64,
    entry_end: u64,
) -> Result<(u64, u64), ReplayError> {
    let window_end = u64::try_from(window.len())
        .ok()
        .and_then(|length| window_start.checked_add(length))
        .ok_or(SegmentError::PositionOverflow)?;
    let mut frame = window_start;
    let mut first = 0;
    loop {
        // Its length word is not in the window: it does not fit.
        let word_end = frame.checked_add(4).ok_or(SegmentError::PositionOverflow)?;
        if word_end > window_end {
            return Ok((frame, first));
        }
        let length = frame_length(window, window_start, frame, entry_end)
            .ok_or(ReplayError::Corrupt { position: frame })?;
        if frame == window_start {
            first = length;
        }
        let next = frame
            .checked_add(length)
            .ok_or(SegmentError::PositionOverflow)?;
        if next > window_end {
            return Ok((frame, first));
        }
        frame = next;
    }
}

/// The length the frame at `frame` takes in its entry, read from `window`
/// (the entry's bytes from `window_start`): aligned, but the entry's last
/// frame may omit its padding. `None` when its length word is outside the
/// window, or its length is not positive or passes the entry's end.
fn frame_length(window: &[u8], window_start: u64, frame: u64, entry_end: u64) -> Option<u64> {
    let offset = usize::try_from(frame.checked_sub(window_start)?).ok()?;
    let word = window.get(offset..offset.checked_add(4)?)?;
    let length = i32::from_le_bytes(word.try_into().ok()?);
    let length = u64::try_from(length).ok().filter(|length| *length > 0)?;
    if frame.checked_add(length)? > entry_end {
        return None;
    }
    let aligned = length
        .checked_add(FRAME_ALIGNMENT - 1)?
        .checked_div(FRAME_ALIGNMENT)?
        .checked_mul(FRAME_ALIGNMENT)?;
    frame
        .checked_add(aligned)?
        .min(entry_end)
        .checked_sub(frame)
}
