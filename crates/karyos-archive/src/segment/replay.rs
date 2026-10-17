// SPDX-License-Identifier: Apache-2.0

//! A recording's range read back for a replay (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A5; SPEC §8.2).
//!
//! [`ReplaySource`] reads a recording's segments without changing them:
//! the frames of `[from, to)` in order, each as the log held it. Data comes
//! as whole frames, a padding or aborted block as its canonical record and
//! extent, and a lost range as a gap. Nothing is skipped silently.
//!
//! - **Range.** `from` must be a frame boundary: the start of an entry, or
//!   a frame start inside a data entry, found by walking its frames. The
//!   replay ends at the last whole frame, fill or gap end at or below `to`.
//!   A recording that is still being written is read up to the position the
//!   caller passes as `to` (the position written when the replay was asked
//!   for); following it live is the live merge's work (A6).
//! - **Integrity.** An entry's data is checked against its CRC: read whole
//!   when it fits the buffer, or in frame-bounded pieces through a running
//!   CRC, in which case a mismatch is reported once its last piece is read.
//! - **Pacing.** [`Rate::Full`] yields as fast as it is polled.
//!   [`Rate::AsRecorded`] and [`Rate::Scaled`] hold each entry until its
//!   record time, measured from the first entry, has passed on the caller's
//!   clock (scaled by parts per million of the recorded pace). Entries
//!   without a record time (0) refuse paced replay with
//!   [`ReplayError::RecordTimeUnknown`]; they never fall back to full
//!   speed.
//!
//! The buffer is allocated once, at [`ReplaySource::open`]; reading
//! allocates only when it opens the next segment's files.

use std::io;
use std::path::{Path, PathBuf};

use super::{
    Entry, EntryKind, Geometry, HEADER, Header, HeaderRead, SegmentError, data_name, entry_offset,
    index_name,
};
use crate::crc32c::Crc32c;
use crate::disk::Disk;

#[cfg(test)]
mod tests;

/// Frames are aligned to 32 bytes in the log and in the segments.
const FRAME_ALIGNMENT: u64 = 32;

/// The pace of a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rate {
    /// As fast as the caller polls.
    Full,
    /// At the cadence the recorder wrote at.
    AsRecorded,
    /// The recorded cadence scaled: parts per million of the recorded pace
    /// (2 000 000 is twice as fast), never 0.
    Scaled {
        /// The scale.
        ppm: u32,
    },
}

/// A replay's error.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The store's files failed to read, or their header is not this
    /// recording's.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// `from` is not a frame boundary of the recording.
    #[error("{position} is not a frame boundary")]
    NotAFrameBoundary {
        /// The position asked for.
        position: u64,
    },
    /// The range lies outside what the recording holds.
    #[error("[{from}, {to}) is outside the recording")]
    OutOfRange {
        /// The range's start.
        from: u64,
        /// Its end.
        to: u64,
    },
    /// A paced replay met an entry without a record time.
    #[error("the entry at {position} has no record time")]
    RecordTimeUnknown {
        /// The entry's start.
        position: u64,
    },
    /// An entry's data failed its CRC, or a frame's length does not hold.
    #[error("the recording is corrupt at {position}")]
    Corrupt {
        /// The entry or frame's start.
        position: u64,
    },
    /// A frame is longer than the replay's buffer.
    #[error("a frame of {length} bytes does not fit the buffer")]
    BufferTooSmall {
        /// The frame's aligned length.
        length: u64,
    },
    /// A scale of 0 parts per million.
    #[error("a scaled replay needs a scale above 0")]
    InvalidScale,
}

/// What a poll yields.
#[derive(Debug, PartialEq, Eq)]
pub enum Step<'a> {
    /// Whole frames at `position`, as the log held them.
    Frames {
        /// Their start.
        position: u64,
        /// The frames, each padded to 32 bytes but the last.
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
    /// The running CRC of a data entry read in pieces, from its start.
    crc: Option<Crc32c>,
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
    /// The first entry's record time and the caller's clock then.
    origin: Option<(u64, u64)>,
    ended: bool,
}

impl<D: Disk> ReplaySource<D> {
    /// Opens recording `recording` in `dir` for the range `[from, to)`,
    /// reading through a buffer of `buffer` bytes (at least the largest
    /// frame).
    ///
    /// # Errors
    ///
    /// [`ReplayError::OutOfRange`] for an empty or reversed range or one
    /// starting before the recording, [`ReplayError::NotAFrameBoundary`],
    /// [`ReplayError::InvalidScale`], and the store's errors.
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
        if rate == (Rate::Scaled { ppm: 0 }) {
            return Err(ReplayError::InvalidScale);
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
        };
        source.seek(from)?;
        Ok(source)
    }

    /// The next position to deliver.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Opens the segment holding `position`.
    fn open_segment(&mut self, base: u64) -> Result<(), ReplayError> {
        let index_path = self.dir.join(index_name(self.recording, base));
        let data_path = self.dir.join(data_name(self.recording, base));
        let missing = |error: io::Error| {
            if error.kind() == io::ErrorKind::NotFound {
                ReplayError::OutOfRange {
                    from: base,
                    to: base,
                }
            } else {
                ReplayError::Segment(error.into())
            }
        };
        let index = self.disk.open(&index_path).map_err(missing)?;
        let data = self.disk.open(&data_path).map_err(missing)?;
        let mut bytes = [0u8; 48];
        self.disk
            .read_at(&index, 0, &mut bytes)
            .map_err(SegmentError::from)?;
        let HeaderRead::Valid(header) = Header::read(Some(&bytes)) else {
            return Err(SegmentError::BadHeader {
                base,
                problem: super::HeaderProblem::Corrupt,
            }
            .into());
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
            return Err(SegmentError::BadHeader {
                base,
                problem: super::HeaderProblem::Mismatch,
            }
            .into());
        }
        let length = self.disk.len(&index).map_err(SegmentError::from)?;
        let entries = length.saturating_sub(HEADER) / super::ENTRY;
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
    /// its last entry; `None` past the recording's last entry.
    fn next_entry(&mut self) -> Result<Option<Entry>, ReplayError> {
        loop {
            let Some(open) = self.open.as_mut() else {
                return Ok(None);
            };
            if open.next_entry < open.entries {
                let at = entry_offset(open.next_entry).ok_or(SegmentError::PositionOverflow)?;
                let mut bytes = [0u8; 32];
                self.disk
                    .read_at(&open.index, at, &mut bytes)
                    .map_err(SegmentError::from)?;
                open.next_entry = open.next_entry.saturating_add(1);
                return match Entry::decode(&bytes) {
                    Some(Ok(entry)) => Ok(Some(entry)),
                    Some(Err((position, kind))) => {
                        Err(SegmentError::UnknownEntryKind { position, kind }.into())
                    }
                    None => Err(ReplayError::Corrupt {
                        position: self.position,
                    }),
                };
            }
            let next = open
                .base
                .checked_add(self.geometry.segment_length)
                .ok_or(SegmentError::PositionOverflow)?;
            if next >= self.to {
                return Ok(None);
            }
            self.open = None;
            match self.open_segment(next) {
                Ok(()) => {}
                Err(ReplayError::OutOfRange { .. }) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    }

    /// Positions the reader at `from`, which must be a frame boundary.
    fn seek(&mut self, from: u64) -> Result<(), ReplayError> {
        self.open_segment(self.geometry.base_of(from))
            .map_err(|error| match error {
                ReplayError::OutOfRange { .. } => ReplayError::OutOfRange { from, to: self.to },
                other => other,
            })?;
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
            if entry.start < from && entry.kind != EntryKind::Gap {
                if entry.kind == EntryKind::Fill {
                    return Err(ReplayError::NotAFrameBoundary { position: from });
                }
                self.walk_to(entry, from)?;
            }
            self.current = Some(Current {
                entry,
                at: from,
                crc: None,
            });
            return Ok(());
        }
    }

    /// Checks `from` is a frame start inside data `entry`.
    fn walk_to(&mut self, entry: Entry, from: u64) -> Result<(), ReplayError> {
        let mut frame = entry.start;
        while frame < from {
            let length = self.frame_length(entry, frame)?;
            frame = frame
                .checked_add(length)
                .ok_or(SegmentError::PositionOverflow)?;
        }
        if frame == from {
            Ok(())
        } else {
            Err(ReplayError::NotAFrameBoundary { position: from })
        }
    }

    /// The aligned length of the frame at `frame`, inside data `entry`.
    fn frame_length(&mut self, entry: Entry, frame: u64) -> Result<u64, ReplayError> {
        let open = self.open.as_ref().ok_or(SegmentError::Failed)?;
        let offset = frame
            .checked_sub(open.base)
            .ok_or(SegmentError::PositionOverflow)?;
        let mut word = [0u8; 4];
        self.disk
            .read_at(&open.data, offset, &mut word)
            .map_err(SegmentError::from)?;
        let length = i32::from_le_bytes(word);
        let corrupt = ReplayError::Corrupt { position: frame };
        let length = u64::try_from(length)
            .ok()
            .filter(|length| *length > 0)
            .ok_or(corrupt)?;
        let aligned = length
            .checked_add(FRAME_ALIGNMENT - 1)
            .map(|length| length / FRAME_ALIGNMENT * FRAME_ALIGNMENT)
            .ok_or(SegmentError::PositionOverflow)?;
        let entry_end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        // The last frame of an entry may omit its alignment padding.
        let end = frame
            .checked_add(aligned)
            .ok_or(SegmentError::PositionOverflow)?;
        if frame
            .checked_add(length)
            .is_none_or(|unpadded| unpadded > entry_end)
        {
            return Err(ReplayError::Corrupt { position: frame });
        }
        Ok(end.min(entry_end).saturating_sub(frame))
    }

    /// Whether the entry is due on the caller's clock, else when it is.
    fn due(&mut self, entry: Entry, now_ns: u64) -> Result<Option<u64>, ReplayError> {
        let ppm = match self.rate {
            Rate::Full => return Ok(None),
            Rate::AsRecorded => 1_000_000,
            Rate::Scaled { ppm } => ppm,
        };
        if entry.time_ns == 0 {
            return Err(ReplayError::RecordTimeUnknown {
                position: entry.start,
            });
        }
        let (recorded, started) = *self.origin.get_or_insert((entry.time_ns, now_ns));
        let elapsed = u128::from(entry.time_ns.saturating_sub(recorded));
        let scaled = elapsed
            .checked_mul(1_000_000)
            .map(|scaled| scaled / u128::from(ppm))
            .and_then(|scaled| u64::try_from(scaled).ok())
            .ok_or(SegmentError::PositionOverflow)?;
        let due = started.saturating_add(scaled);
        Ok((now_ns < due).then_some(due))
    }

    /// The next step on the caller's clock, `now_ns`.
    ///
    /// # Errors
    ///
    /// [`ReplayError::RecordTimeUnknown`] for a paced replay of an entry
    /// without a record time, [`ReplayError::Corrupt`],
    /// [`ReplayError::BufferTooSmall`], and the store's errors.
    pub fn poll(&mut self, now_ns: u64) -> Result<Step<'_>, ReplayError> {
        if self.ended {
            return Ok(Step::End {
                position: self.position,
            });
        }
        let current = match self.current {
            Some(current) => current,
            None => match self.next_entry()? {
                Some(entry) if entry.start == self.position => Current {
                    entry,
                    at: entry.start,
                    crc: None,
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
        // Pacing applies at an entry's first delivery.
        if (current.at == entry.start || self.origin.is_none())
            && let Some(until_ns) = self.due(entry, now_ns)?
        {
            return Ok(Step::Wait { until_ns });
        }
        let entry_end = entry.end().ok_or(SegmentError::PositionOverflow)?;
        match entry.kind {
            EntryKind::Gap => {
                let to = entry_end.min(self.to);
                let from = current.at;
                self.advance(to, entry_end);
                Ok(Step::Gap { from, to })
            }
            EntryKind::Fill => {
                if entry_end > self.to {
                    return Ok(self.end());
                }
                let record = self.read_fill(entry)?;
                self.advance(entry_end, entry_end);
                let record = self.buffer.get(..record).ok_or(SegmentError::Failed)?;
                Ok(Step::Fill {
                    position: entry.start,
                    record,
                    extent: entry.length,
                })
            }
            EntryKind::Data => self.data(current, entry_end),
        }
    }

    fn end(&mut self) -> Step<'static> {
        self.ended = true;
        self.current = None;
        Step::End {
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

    fn read_fill(&mut self, entry: Entry) -> Result<usize, ReplayError> {
        let open = self.open.as_ref().ok_or(SegmentError::Failed)?;
        let offset = entry
            .start
            .checked_sub(open.base)
            .ok_or(SegmentError::PositionOverflow)?;
        let record = self
            .buffer
            .get_mut(..super::FILL_RECORD)
            .ok_or(ReplayError::BufferTooSmall { length: 32 })?;
        self.disk
            .read_at(&open.data, offset, record)
            .map_err(SegmentError::from)?;
        if crate::crc32c::crc32c(record) != entry.data_crc {
            return Err(ReplayError::Corrupt {
                position: entry.start,
            });
        }
        Ok(super::FILL_RECORD)
    }

    /// The next frames of data `current`, as many whole frames as fit the
    /// buffer and the range.
    fn data(&mut self, current: Current, entry_end: u64) -> Result<Step<'_>, ReplayError> {
        let limit = entry_end.min(self.to);
        let room = u64::try_from(self.buffer.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let whole_entry = current.at == current.entry.start && entry_end <= limit;
        let length = entry_end.saturating_sub(current.at);
        // The whole entry fits: read it, check its CRC, deliver it.
        let end = if whole_entry && length <= room {
            entry_end
        } else {
            let mut end = current.at;
            loop {
                if end >= limit {
                    break;
                }
                let frame = self.frame_length(current.entry, end)?;
                let next = end
                    .checked_add(frame)
                    .ok_or(SegmentError::PositionOverflow)?;
                if next > limit || next.saturating_sub(current.at) > room {
                    if end == current.at {
                        if next > limit {
                            return Ok(self.end());
                        }
                        return Err(ReplayError::BufferTooSmall { length: frame });
                    }
                    break;
                }
                end = next;
            }
            end
        };
        let open = self.open.as_ref().ok_or(SegmentError::Failed)?;
        let offset = current
            .at
            .checked_sub(open.base)
            .ok_or(SegmentError::PositionOverflow)?;
        let length = usize::try_from(end.saturating_sub(current.at))
            .map_err(|_| SegmentError::PositionOverflow)?;
        let bytes = self.buffer.get_mut(..length).ok_or(SegmentError::Failed)?;
        self.disk
            .read_at(&open.data, offset, bytes)
            .map_err(SegmentError::from)?;
        // The entry's CRC covers it whole: a running CRC over its pieces,
        // checked with the last. A replay that starts inside an entry, or
        // stops before its end, cannot check it.
        let tracking = if current.at == current.entry.start {
            Some(Crc32c::new())
        } else {
            current.crc
        };
        if let Some(mut crc) = tracking {
            crc.update(bytes);
            if end == entry_end && crc.finish() != current.entry.data_crc {
                return Err(ReplayError::Corrupt {
                    position: current.entry.start,
                });
            }
            if let Some(current) = self.current.as_mut() {
                current.crc = Some(crc);
            }
        }
        let position = current.at;
        self.advance(end, entry_end);
        let bytes = self.buffer.get(..length).ok_or(SegmentError::Failed)?;
        Ok(Step::Frames { position, bytes })
    }
}
