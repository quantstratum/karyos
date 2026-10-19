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
pub struct Following<T: TermBytes = HeapTerms> {
    reader: SenderRead<Arc<LogBuffer<T>>>,
    link: Arc<GenerationLink<T>>,
    base: u64,
    /// How a fenced reader asks for a new member at the head.
    rejoin: Option<Box<RejoinHook<T>>>,
    /// The seal the reader was fenced at, while its rejoin is answered.
    fenced: Option<u64>,
    /// What keeps the rejoined member's stream: dropped with the source,
    /// after the reader, or when a later rejoin replaces it.
    guard: Option<Box<dyn Send>>,
}

/// A host's answer to a fenced reader that asks to rejoin its stream.
#[expect(
    clippy::large_enum_variant,
    reason = "made once per rejoin, a control-path event, and moved once to the source; boxing the member would only add an allocation"
)]
pub enum Rejoin<T: TermBytes = HeapTerms> {
    /// Not answered yet: the reader asks again on a later read.
    Waiting,
    /// A new optional member of the stream's current generation, admitted
    /// at its head: its reader, the link it follows, the stream position
    /// its mapping starts at, and what keeps its stream (the driver's
    /// lease, which the Archive does not know).
    Joined {
        /// The new member's reader.
        reader: SenderRead<Arc<LogBuffer<T>>>,
        /// The link it follows at the next cutover.
        link: Arc<GenerationLink<T>>,
        /// The stream position its mapping starts at.
        base: u64,
        /// What keeps its stream.
        guard: Box<dyn Send>,
    },
    /// The stream cannot be rejoined (removed, retiring): the recording
    /// ends at the seal, as a fenced recording without a hook does.
    Refused,
}

/// How a host answers a fenced reader's request to rejoin: asked on each
/// read until it answers [`Rejoin::Joined`] or [`Rejoin::Refused`]. It
/// runs on the Archive's thread, so a host whose driver runs elsewhere
/// answers through a channel.
pub type RejoinHook<T> = dyn FnMut() -> Rejoin<T> + Send;

impl<T: TermBytes> std::fmt::Debug for Following<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Following")
            .field("reader", &self.reader)
            .field("link", &self.link)
            .field("base", &self.base)
            .field("rejoins", &self.rejoin.is_some())
            .field("fenced", &self.fenced)
            .finish_non_exhaustive()
    }
}

impl<T: TermBytes> Following<T> {
    /// `reader`, whose mapping starts at stream position `base`, following
    /// `link`.
    pub const fn new(
        reader: SenderRead<Arc<LogBuffer<T>>>,
        link: Arc<GenerationLink<T>>,
        base: u64,
    ) -> Self {
        Self {
            reader,
            link,
            base,
            rejoin: None,
            fenced: None,
            guard: None,
        }
    }

    /// As [`Following::new`], for an `async` recording that resumes after
    /// a lap: fenced at a cutover, the reader asks `hook` for a new
    /// member at the stream's head and reads on from there, with
    /// [`Frames::Rejoined`] for the gap (mapping-generations.md,
    /// "Recordings"). Only such a recording takes a hook; the recorder
    /// refuses a rejoin for any other.
    pub fn rejoining(
        reader: SenderRead<Arc<LogBuffer<T>>>,
        link: Arc<GenerationLink<T>>,
        base: u64,
        hook: Box<RejoinHook<T>>,
    ) -> Self {
        Self {
            rejoin: Some(hook),
            ..Self::new(reader, link, base)
        }
    }

    /// The reader was fenced at `at`: a rejoin, while the host has not
    /// answered, or the end.
    fn after_fence(&mut self, at: u64) -> Result<Frames, SourceError> {
        let Some(hook) = self.rejoin.as_mut() else {
            return Ok(Frames::Fenced { at });
        };
        match hook() {
            Rejoin::Waiting => {
                self.fenced = Some(at);
                Ok(Frames::Pending)
            }
            Rejoin::Refused => {
                self.fenced = None;
                self.rejoin = None;
                Ok(Frames::Fenced { at })
            }
            Rejoin::Joined {
                reader,
                link,
                base,
                guard,
            } => {
                let to = base
                    .checked_add(reader.position())
                    .ok_or(SourceError::Invariant)?;
                // A member of a later generation starts at or after the
                // seal its predecessor was fenced at.
                if to < at {
                    return Err(SourceError::Invariant);
                }
                self.reader = reader;
                self.link = link;
                self.base = base;
                // The old reader is dropped first, then the old guard.
                self.guard = Some(guard);
                self.fenced = None;
                Ok(Frames::Rejoined { from: at, to })
            }
        }
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
        // The link refuses a base whose mapping could pass `2^63`, so the
        // sum is below it; the fallback is never taken.
        let position = self.base.checked_add(self.reader.position());
        debug_assert!(position.is_some(), "a mapping past 2^63");
        position.unwrap_or(u64::MAX)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        // Fenced and waiting for the host: ask again.
        if let Some(at) = self.fenced {
            return self.after_fence(at);
        }
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
            // A bare reader has no hook: only this source rejoins.
            Frames::Rejoined { .. } => return Err(SourceError::Invariant),
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
                    Next::End => return self.after_fence(at),
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
