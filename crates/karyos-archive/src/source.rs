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

use std::sync::Arc;

use karyos_client::{GenerationLink, Next, Successor};
use karyos_sys::frame::FRAME_ALIGNMENT;
use karyos_sys::log_buffer::{
    BufferOwner, LogBuffer, ReadError, ReadOrigin, ReadOutcome, SenderRead,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::recorder::{FrameSource, Frames, SourceError};

#[cfg(test)]
mod tests;

/// A source with a guard the recording keeps until it drops the source:
/// what the source needs alive while it is read, such as the driver's
/// lease on the recorded stream, which keeps a removed stream until its
/// seal is positioned and read. The Archive does not know what the guard
/// is (SPEC §14). The source is dropped first, then the guard.
#[derive(Debug)]
pub struct Guarded<S, G> {
    // Declared before `guard`: fields drop in declaration order.
    source: S,
    guard: G,
}

impl<S, G> Guarded<S, G> {
    /// `source`, kept with `guard`.
    pub const fn new(source: S, guard: G) -> Self {
        Self { source, guard }
    }

    /// The source and its guard, apart.
    pub fn into_parts(self) -> (S, G) {
        (self.source, self.guard)
    }
}

impl<S: FrameSource, G> FrameSource for Guarded<S, G> {
    fn position(&self) -> u64 {
        self.source.position()
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        self.source.read(out)
    }

    fn consumed(&mut self, position: u64) -> Result<(), SourceError> {
        self.source.consumed(position)
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        self.source.resume(to)
    }
}

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
            // A seal with a successor: a bare reader holds no link to it, so
            // it is fenced there. `Following` asks its link instead.
            Ok(ReadOutcome::Pending) => Ok(match self.seal_position() {
                Some(at) if at == position && self.sealed_with_successor() => Frames::Fenced { at },
                Some(at) if at == position => Frames::Sealed { at },
                _ => Frames::Pending,
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

/// A recording reader that follows its stream's mapping cutovers
/// (quantstratum-docs: karyos/design/mapping-generations.md,
/// "Recordings"): the reader of the current mapping, the generation link
/// that offers it the successor's, and the mapping's base. It reports
/// stream positions (the mapping's local positions plus the base), so a
/// recording is continuous across a cutover.
///
/// At a seal with a successor it takes the offered successor reader:
/// [`Frames::Cutover`] at the seal, and the next read is the successor's.
/// While the successor is not offered yet it is [`Frames::Pending`]; a
/// fenced reader gets [`Frames::Fenced`] at the seal.
#[derive(Debug)]
pub struct Following<T: TermBytes = HeapTerms> {
    reader: SenderRead<Arc<LogBuffer<T>>>,
    link: Arc<GenerationLink<T>>,
    base: u64,
}

impl<T: TermBytes> Following<T> {
    /// `reader`, whose mapping starts at stream position `base`, following
    /// `link`.
    pub const fn new(
        reader: SenderRead<Arc<LogBuffer<T>>>,
        link: Arc<GenerationLink<T>>,
        base: u64,
    ) -> Self {
        Self { reader, link, base }
    }

    /// The stream position of the reader's local `position`.
    fn stream(&self, position: u64) -> Result<u64, SourceError> {
        self.base
            .checked_add(position)
            .ok_or(SourceError::Invariant)
    }

    /// The reader's local position of the stream's `position`.
    fn local(&self, position: u64) -> Result<u64, SourceError> {
        position
            .checked_sub(self.base)
            .ok_or(SourceError::Invariant)
    }
}

impl<T: TermBytes> FrameSource for Following<T> {
    fn position(&self) -> u64 {
        // The link refuses a base whose mapping could pass `2^63`.
        self.base.saturating_add(self.reader.position())
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        Ok(match self.reader.read(out)? {
            Frames::Copied {
                position,
                len,
                next,
            } => Frames::Copied {
                position: self.stream(position)?,
                len,
                next: self.stream(next)?,
            },
            Frames::Fill { position, next } => Frames::Fill {
                position: self.stream(position)?,
                next: self.stream(next)?,
            },
            Frames::Pending => Frames::Pending,
            Frames::Sealed { at } => Frames::Sealed {
                at: self.stream(at)?,
            },
            Frames::Lost { from, to } => Frames::Lost {
                from: self.stream(from)?,
                to: self.stream(to)?,
            },
            // The reader's seal marks a successor: the link says whether
            // this reader moves to it.
            Frames::Fenced { at } | Frames::Cutover { at } => {
                let at = self.stream(at)?;
                match self.link.next(true) {
                    Next::Moved {
                        base,
                        successor: Successor::Recording(reader),
                    } => {
                        // The successor starts exactly at the seal.
                        if base != at {
                            return Err(SourceError::Invariant);
                        }
                        self.reader = *reader;
                        self.base = base;
                        Frames::Cutover { at }
                    }
                    Next::Wait => Frames::Pending,
                    Next::End => Frames::Fenced { at },
                    // The driver offers a recording only a recording cell.
                    _ => return Err(SourceError::Invariant),
                }
            }
        })
    }

    fn consumed(&mut self, position: u64) -> Result<(), SourceError> {
        let position = self.local(position)?;
        self.reader.consumed(position)
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        let to = self.local(to)?;
        let resumed = self.reader.resume(to)?;
        self.stream(resumed)
    }
}
