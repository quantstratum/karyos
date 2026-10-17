// SPDX-License-Identifier: Apache-2.0

//! A lane's log as a recording's [`FrameSource`] (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A4): the network sender's read
//! capability, [`SenderRead`], over a cell the driver admits for the
//! recording (`required`, or `async` as an optional participant).
//!
//! A copy ends at its last frame's unpadded end; the frames sit at 32-byte
//! strides in the log, so the record is padded with zeros to the cursor
//! after the copy, and the segment holds the frames exactly where the log
//! does.

use karyos_sys::frame::FRAME_ALIGNMENT;
use karyos_sys::log_buffer::{BufferOwner, ReadError, ReadOrigin, ReadOutcome, SenderRead};

use crate::recorder::{FrameSource, Frames, SourceError};

#[cfg(test)]
mod tests;

impl<O: BufferOwner> FrameSource for SenderRead<O> {
    fn position(&self) -> u64 {
        Self::position(self)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let position = Self::position(self);
        // Whole strides only: a frame copied then fits with its padding.
        let stride = usize::try_from(FRAME_ALIGNMENT).map_err(|_| SourceError::Invariant)?;
        let whole = out.len() - out.len() % stride;
        let out = out.get_mut(..whole).ok_or(SourceError::Invariant)?;
        match self.read_committed(position, ReadOrigin::Cursor, out) {
            Ok(ReadOutcome::Copied { len, next }) => {
                let extent = next
                    .checked_sub(position)
                    .and_then(|extent| usize::try_from(extent).ok())
                    .ok_or(SourceError::Invariant)?;
                // The last frame's alignment padding, as the log holds it.
                out.get_mut(len..extent)
                    .ok_or(SourceError::Invariant)?
                    .fill(0);
                Ok(Frames::Copied {
                    position,
                    len: extent,
                    next,
                })
            }
            Ok(ReadOutcome::Canonical { next, .. }) => Ok(Frames::Fill { position, next }),
            Ok(ReadOutcome::Pending) => Ok(if self.seal_position() == Some(position) {
                Frames::Sealed { at: position }
            } else {
                Frames::Pending
            }),
            Err(ReadError::Unavailable { lowest }) => Ok(Frames::Lost {
                from: position,
                to: lowest,
            }),
            // Not ready yet, or a word 0 still being retried (C-9).
            Err(ReadError::Retry | ReadError::CorruptTerm { .. }) => Ok(Frames::Pending),
            Err(ReadError::Revoked) => Err(SourceError::Revoked),
            Err(ReadError::Faulted { position }) => Err(SourceError::Faulted { position }),
            Err(
                ReadError::Invariant
                | ReadError::TooSmall { .. }
                | ReadError::BadRequest
                | ReadError::Budget,
            ) => Err(SourceError::Invariant),
        }
    }

    fn consumed(&mut self, position: u64) -> Result<(), SourceError> {
        // A copy that fills the buffer can end inside a fragmented message:
        // the publisher may move past the last whole message only, as the
        // network sender releases a submission.
        match self.boundary_at_or_below(position) {
            Some(boundary) => self.sent(boundary).map_err(|_| SourceError::Invariant),
            None => Ok(()),
        }
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        // A lapped optional reader rejoins at the reserved head, a block
        // boundary at or above the floor `to`.
        match self.rejoin_at_head() {
            Ok(resumed) if resumed >= to => Ok(resumed),
            Err(ReadError::Retry) => Err(SourceError::Busy),
            Err(ReadError::Revoked) => Err(SourceError::Revoked),
            Err(ReadError::Faulted { position }) => Err(SourceError::Faulted { position }),
            Ok(_) | Err(_) => Err(SourceError::Invariant),
        }
    }
}
