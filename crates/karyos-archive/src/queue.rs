// SPDX-License-Identifier: Apache-2.0

//! A frame source over records its owner queues (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M10 and owner item 7):
//! a process with no log of its own, such as the management agent writing
//! its operations journal, records through the [`Recorder`] all the same.
//!
//! [`QueueSource::push`] lays each record out as one unfragmented DATA frame
//! at the queue's tail, as a log would hold it: a 32-byte header, the
//! payload, zeros to the frame alignment, and a padding block to the term's
//! end first when the frame does not fit the rest of the term. The recorder
//! then copies the frames into the recording, which the Archive's readers
//! replay like any other. The source is never lapped: a recording of it is
//! [`Mode::Required`](crate::recorder::Mode::Required), and the queue holds
//! at most [`QueueConfig::max_bytes`] not yet consumed.
//!
//! [`Recorder`]: crate::recorder::Recorder

#[cfg(test)]
mod tests;

use std::collections::VecDeque;

use karyos_sys::frame::{FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, Word0};

use crate::recorder::{FrameSource, Frames, SourceError};
use crate::segment::{FILL_RECORD, Geometry};

/// What a queue lays its frames out with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueueConfig {
    /// The recording's geometry: its term length bounds a frame.
    pub geometry: Geometry,
    /// The stream id every frame carries.
    pub stream_id: i32,
    /// The session id every frame carries.
    pub session_id: i32,
    /// The term id of the term at position 0.
    pub initial_term_id: i32,
    /// Bytes queued at most, not yet consumed (padding included).
    pub max_bytes: u64,
}

impl QueueConfig {
    /// Frames of `stream_id` and `session_id` in `geometry`, from term 0,
    /// with at most `max_bytes` queued.
    #[must_use]
    pub const fn new(geometry: Geometry, stream_id: i32, session_id: i32, max_bytes: u64) -> Self {
        Self {
            geometry,
            stream_id,
            session_id,
            initial_term_id: 0,
            max_bytes,
        }
    }
}

/// Why a record was not queued; nothing was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QueueError {
    /// The frame would be longer than a term.
    #[error("a record of {length} bytes does not fit a term")]
    TooLarge {
        /// The payload's length.
        length: usize,
    },
    /// The queue holds [`QueueConfig::max_bytes`] already.
    #[error("the queue is full")]
    Full,
    /// The queue was sealed.
    #[error("the queue is sealed")]
    Sealed,
    /// A position or term id would overflow.
    #[error("the queue's positions are exhausted")]
    Exhausted,
}

#[derive(Debug)]
enum Entry {
    /// A frame with its alignment padding.
    Frame(Vec<u8>),
    /// A padding block of `extent` bytes to the term's end.
    Fill { extent: u32 },
}

impl Entry {
    fn extent(&self) -> Option<u64> {
        match self {
            Self::Frame(bytes) => u64::try_from(bytes.len()).ok(),
            Self::Fill { extent } => Some(u64::from(*extent)),
        }
    }
}

/// The frame source over queued records (see the module).
#[derive(Debug)]
pub struct QueueSource {
    config: QueueConfig,
    /// Where the next read starts: the first entry's position.
    position: u64,
    /// Where the next record goes.
    tail: u64,
    entries: VecDeque<Entry>,
    sealed: bool,
}

impl QueueSource {
    /// A queue whose first record goes at `position`, the recording's
    /// written position, a multiple of the frame alignment.
    ///
    /// # Errors
    ///
    /// [`QueueError::Exhausted`] for a position that is not aligned.
    pub fn new(config: QueueConfig, position: u64) -> Result<Self, QueueError> {
        if !position.is_multiple_of(u64::from(FRAME_ALIGNMENT)) {
            return Err(QueueError::Exhausted);
        }
        Ok(Self {
            config,
            position,
            tail: position,
            entries: VecDeque::new(),
            sealed: false,
        })
    }

    /// Where the next record goes: the end of the last one queued.
    #[must_use]
    pub const fn tail(&self) -> u64 {
        self.tail
    }

    /// Bytes queued and not yet consumed.
    #[must_use]
    pub fn queued(&self) -> u64 {
        // The tail is never behind the read position.
        self.tail.abs_diff(self.position)
    }

    /// Queues `payload` as one DATA frame; returns the position after it,
    /// which the recording covers once it has recorded the frame.
    ///
    /// # Errors
    ///
    /// [`QueueError`]; nothing is queued then.
    pub fn push(&mut self, payload: &[u8]) -> Result<u64, QueueError> {
        if self.sealed {
            return Err(QueueError::Sealed);
        }
        let term_length = u64::from(self.config.geometry.term_length());
        let too_large = QueueError::TooLarge {
            length: payload.len(),
        };
        let length = u64::try_from(payload.len())
            .ok()
            .and_then(|length| length.checked_add(u64::from(HEADER_LENGTH)))
            .ok_or(too_large)?;
        let aligned = length
            .checked_next_multiple_of(u64::from(FRAME_ALIGNMENT))
            .filter(|aligned| *aligned <= term_length)
            .ok_or(too_large)?;
        let offset = self.tail % term_length;
        let room = term_length
            .checked_sub(offset)
            .ok_or(QueueError::Exhausted)?;
        // A frame that does not fit the term's rest goes in the next term,
        // after a padding block, as a log lays it out.
        let fill = (aligned > room).then_some(room);
        let at = self.tail.checked_add(fill.unwrap_or(0));
        let end = at.and_then(|at| at.checked_add(aligned));
        let (Some(at), Some(end)) = (at, end) else {
            return Err(QueueError::Exhausted);
        };
        let queued = end
            .checked_sub(self.position)
            .ok_or(QueueError::Exhausted)?;
        if queued > self.config.max_bytes {
            return Err(QueueError::Full);
        }
        let frame = self.frame(at, length, aligned, payload)?;
        if let Some(extent) = fill {
            let extent = u32::try_from(extent).map_err(|_| QueueError::Exhausted)?;
            self.entries.push_back(Entry::Fill { extent });
        }
        self.entries.push_back(Entry::Frame(frame));
        self.tail = end;
        Ok(end)
    }

    /// Seals the queue: once what it holds is read, it reads as sealed at
    /// its tail, and the recording ends there.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// The term id and term offset of `position`.
    fn term(&self, position: u64) -> Result<(i32, i32), QueueError> {
        let term_length = u64::from(self.config.geometry.term_length());
        let term = i32::try_from(position / term_length).map_err(|_| QueueError::Exhausted)?;
        let term_id = self
            .config
            .initial_term_id
            .checked_add(term)
            .ok_or(QueueError::Exhausted)?;
        let offset = i32::try_from(position % term_length).map_err(|_| QueueError::Exhausted)?;
        Ok((term_id, offset))
    }

    /// The frame of `payload` at `at`: header, payload, alignment zeros.
    fn frame(
        &self,
        at: u64,
        length: u64,
        aligned: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, QueueError> {
        let (term_id, term_offset) = self.term(at)?;
        let frame_length = i32::try_from(length).map_err(|_| QueueError::Exhausted)?;
        let flags = Flags::new(true, true, false, false, Lane::ZERO);
        let word0 = Word0::new(frame_length, flags, FrameType::Data).pack();
        let aligned = usize::try_from(aligned).map_err(|_| QueueError::Exhausted)?;
        let mut frame = Vec::with_capacity(aligned);
        frame.extend_from_slice(&word0.to_le_bytes());
        frame.extend_from_slice(&term_offset.to_le_bytes());
        frame.extend_from_slice(&self.config.session_id.to_le_bytes());
        frame.extend_from_slice(&self.config.stream_id.to_le_bytes());
        frame.extend_from_slice(&term_id.to_le_bytes());
        frame.extend_from_slice(&0i64.to_le_bytes());
        frame.extend_from_slice(payload);
        frame.resize(aligned, 0);
        Ok(frame)
    }

    /// The canonical PAD record of a block at `at` of `extent` bytes.
    fn fill_record(&self, at: u64, extent: u32, out: &mut [u8]) -> Result<(), SourceError> {
        let out = out.get_mut(..FILL_RECORD).ok_or(SourceError::Invariant)?;
        let (term_id, term_offset) = self.term(at).map_err(|_| SourceError::Invariant)?;
        let length = i32::try_from(HEADER_LENGTH).map_err(|_| SourceError::Invariant)?;
        let flags = Flags::new(false, false, false, false, Lane::ZERO);
        let word0 = Word0::new(length, flags, FrameType::Pad).pack();
        let fields: [&[u8]; 6] = [
            &word0.to_le_bytes(),
            &term_offset.to_le_bytes(),
            &self.config.session_id.to_le_bytes(),
            &self.config.stream_id.to_le_bytes(),
            &term_id.to_le_bytes(),
            &i64::from(extent).to_le_bytes(),
        ];
        let mut cursor = 0usize;
        for bytes in fields {
            let end = cursor
                .checked_add(bytes.len())
                .ok_or(SourceError::Invariant)?;
            out.get_mut(cursor..end)
                .ok_or(SourceError::Invariant)?
                .copy_from_slice(bytes);
            cursor = end;
        }
        Ok(())
    }
}

impl FrameSource for QueueSource {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let position = self.position;
        let Some(entry) = self.entries.front() else {
            return Ok(if self.sealed {
                Frames::Sealed { at: position }
            } else {
                Frames::Pending
            });
        };
        let next = entry
            .extent()
            .and_then(|extent| position.checked_add(extent))
            .ok_or(SourceError::Invariant)?;
        match entry {
            Entry::Frame(bytes) => {
                out.get_mut(..bytes.len())
                    .ok_or(SourceError::Invariant)?
                    .copy_from_slice(bytes);
                Ok(Frames::Copied {
                    position,
                    len: bytes.len(),
                    next,
                })
            }
            Entry::Fill { extent } => {
                self.fill_record(position, *extent, out)?;
                Ok(Frames::Fill { position, next })
            }
        }
    }

    fn consumed(&mut self, position: u64) -> Result<(), SourceError> {
        // Only the end of the entry a read returned.
        let next = self
            .entries
            .front()
            .and_then(Entry::extent)
            .and_then(|extent| self.position.checked_add(extent));
        if next != Some(position) {
            return Err(SourceError::Invariant);
        }
        let _ = self.entries.pop_front();
        self.position = position;
        Ok(())
    }

    fn resume(&mut self, _to: u64) -> Result<u64, SourceError> {
        // Never lapped: nothing is lost to resume after.
        Err(SourceError::Invariant)
    }
}
